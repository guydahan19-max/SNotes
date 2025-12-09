import express from "express";
import path from "path";
import bodyParser from "body-parser";
import bcrypt from "bcrypt";
import session from "express-session";
import passport from "passport";
import { Strategy as LocalStrategy } from "passport-local";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import pg from "pg";
import dotenv from "dotenv";
dotenv.config();

const { Client } = pg;

// ================= Database =================
const client = new Client({
  user: "postgres",
  host: "localhost",
  database: process.env.DATABASE,
  password: process.env.PASSWORD_DB,
  port: 5432
});

// ================= Start Server =================
async function startServer() {
  await client.connect();
  const app = express();

  // ================= Express Settings =================
  app.set("view engine", "ejs");
  app.set("views", path.join(process.cwd(), "views"));
  app.use(express.static("client"));
  app.use(bodyParser.urlencoded({ extended: true }));
  app.use(bodyParser.json());

  // ================= Session =================
  app.use(session({
    secret: process.env.SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 1000 * 60 * 60 * 24 }
  }));

  app.use(passport.initialize());
  app.use(passport.session());

  // ================= Local Strategy =================
  passport.use(new LocalStrategy(
    { usernameField: "email" },
    async (email, password, done) => {
      try {
        const res = await client.query("SELECT * FROM users WHERE email = $1", [email]);
        const user = res.rows[0];
        if (!user) return done(null, false, { message: "Incorrect email." });

        const match = await bcrypt.compare(password, user.password);
        if (!match) return done(null, false, { message: "Incorrect password." });

        return done(null, user);
      } catch (err) { return done(err); }
    }
  ));

  // ================= Google Strategy =================
  passport.use(new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: process.env.GOOGLE_CALLBACK_URL
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        const email = profile.emails?.[0]?.value;
        if (!email) return done(new Error("No email found"), null);

        const res = await client.query("SELECT * FROM users WHERE email = $1", [email]);
        if (res.rows.length > 0) return done(null, res.rows[0]);

        const newUser = await client.query(
          `INSERT INTO users (name, email, password, imgurl)
           VALUES ($1, $2, $3, $4) RETURNING *`,
          [
            profile.displayName,
            email,
            "google_oauth",
            profile.photos?.[0]?.value || "/assets/images/default.png"
          ]
        );
        return done(null, newUser.rows[0]);
      } catch (err) { return done(err, null); }
    }
  ));

  // ================= Serialization =================
  passport.serializeUser((user, done) => done(null, user.id));
  passport.deserializeUser(async (id, done) => {
    try {
      const res = await client.query("SELECT * FROM users WHERE id = $1", [id]);
      done(null, res.rows[0]);
    } catch (err) { done(err); }
  });

  // ================= Middleware =================
  function checkAuthenticated(req, res, next) {
    if (req.isAuthenticated()) return next();
    res.redirect("/login");
  }
  function checkNotAuthenticated(req, res, next) {
    if (req.isAuthenticated()) return res.redirect("/");
    next();
  }

  // ================= Routes =================
  app.get("/", async (req, res) => {
    let notes = [];
    if (req.isAuthenticated()) {
      try {
        const result = await client.query("SELECT * FROM notes WHERE user_id = $1 ORDER BY id DESC", [req.user.id]);
        notes = result.rows;
      } catch (err) { console.error(err); }
    }
    res.render("index", {
      notes,
      user: req.user || null,
      isAuth: req.isAuthenticated()
    });
  });

  // ---------- Sign Up ----------
  app.get("/sign-up", checkNotAuthenticated, (req, res) => res.render("sign-up"));
  app.post("/sign-up", async (req, res, next) => {
    try {
      const { name, email, password, imgURL } = req.body;
      const existingUser = await client.query("SELECT * FROM users WHERE email = $1", [email]);
      if (existingUser.rows.length > 0) return res.render("sign-up", { error: "Email already in use" });

      const hashedPassword = await bcrypt.hash(password, 10);
      const insertResult = await client.query(
        "INSERT INTO users (name, email, password, imgurl) VALUES ($1, $2, $3, $4) RETURNING *",
        [name, email, hashedPassword, imgURL || "/assets/images/default.png"]
      );
      const newUser = insertResult.rows[0];

      req.login(newUser, (err) => { if (err) return next(err); res.redirect("/"); });
    } catch (err) {
      console.error(err);
      res.render("sign-up", { error: "Something went wrong, try again." });
    }
  });

  // ---------- Login ----------
  app.get("/login", checkNotAuthenticated, (req, res) => res.render("login"));
  app.post("/login",
    passport.authenticate("local", { successRedirect: "/", failureRedirect: "/login" })
  );

  // ---------- Google Auth ----------
  app.get("/auth/google", passport.authenticate("google", { scope: ["profile", "email"] }));
  app.get("/auth/google/callback",
    passport.authenticate("google", { failureRedirect: "/login", successRedirect: "/" })
  );
app.get("/profile", checkAuthenticated, (req, res) => {
   res.render("profile.ejs", { user: req.user });
});
app.get("/edit", checkAuthenticated, (req, res) => {
   res.render("edit.ejs", { user: req.user });
});

  // ---------- Logout ----------
  app.get("/logout", (req, res, next) => {
    if (req.isAuthenticated()) {
      req.logout(err => { if (err) return next(err); res.redirect("/"); });
    } else { res.redirect("/"); }
  });
  
  // ---------- Edit Profile ----------
app.post("/edit", checkAuthenticated, async (req, res) => {
  try {
    const { name, imgurl } = req.body;

    await client.query(
      "UPDATE users SET name=$1, imgurl=$2 WHERE id=$3",
      [name, imgurl, req.user.id]
    );

    // עדכון אובייקט המשתמש ב-session כך שהשינויים יופיעו מיד
    req.user.name = name;
    req.user.imgurl = imgurl;

    res.redirect("/profile"); // או "/edit" אם רוצים להישאר בדף
  } catch (err) {
    console.error(err);
    res.render("edit", { user: req.user, error: "Error updating profile" });
  }
});


  // ---------- Add Note ----------
  app.post("/add-note", checkAuthenticated, async (req, res) => {
    try {
      const { noteTitle, noteContent } = req.body;
      if (!noteTitle || !noteContent) return res.status(400).send("Missing fields");

      const now = new Date();
      const time = now.getHours() + ":" + String(now.getMinutes()).padStart(2, "0");

      const colors = ['note-blue','note-green','note-yellow','note-pink'];
      const color = colors[Math.floor(Math.random()*colors.length)];

      const insertRes = await client.query(
        "INSERT INTO notes (user_id, title, content, time, color, done) VALUES ($1,$2,$3,$4,$5,$6) RETURNING *",
        [req.user.id, noteTitle, noteContent, time, color, false]
      );

      res.json({ id: insertRes.rows[0].id });
    } catch (err) { console.error(err); res.status(500).send("Error saving note"); }
  });

  // ---------- Edit Multiple Notes ----------
  app.post("/edit-multiple-notes", checkAuthenticated, async (req, res) => {
    try {
      const { updates } = req.body;
      for (const u of updates) {
        await client.query(
          "UPDATE notes SET title=$1, content=$2 WHERE id=$3 AND user_id=$4",
          [u.title, u.content, u.noteId, req.user.id]
        );
      }
      res.sendStatus(200);
    } catch (err) {
      console.error(err);
      res.status(500).send("Error saving notes");
    }
  });

  // ---------- Edit Note ----------
  app.post("/edit-note", checkAuthenticated, async (req, res) => {
    try {
      const { noteId, newTitle, newContent } = req.body;
      await client.query(
        "UPDATE notes SET title=$1, content=$2 WHERE id=$3 AND user_id=$4",
        [newTitle, newContent, noteId, req.user.id]
      );
      res.sendStatus(200);
    } catch (err) { console.error(err); res.status(500).send("Error editing note"); }
  });

  // ---------- Delete Note ----------
  app.post("/delete-note", checkAuthenticated, async (req, res) => {
    try {
      const { noteId } = req.body;
      await client.query("DELETE FROM notes WHERE id=$1 AND user_id=$2", [noteId, req.user.id]);
      res.sendStatus(200);
    } catch (err) { console.error(err); res.status(500).send("Error deleting note"); }
  });

  // ---------- Mark Done ----------
  app.post("/mark-done", checkAuthenticated, async (req, res) => {
    try {
      const { noteId } = req.body;
      await client.query("UPDATE notes SET done=true WHERE id=$1 AND user_id=$2", [noteId, req.user.id]);
      res.sendStatus(200);
    } catch (err) { console.error(err); res.status(500).send("Error marking done"); }
  });

  // ================= Start Express Server =================
  app.listen(3000, () => console.log("Server running on http://localhost:3000"));
}

startServer();
