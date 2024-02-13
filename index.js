import "dotenv/config";
import express from "express";
import bodyParser from "body-parser";
import  pg  from "pg";
import bcrypt from "bcrypt";
import session from "express-session";
import passport from "passport";
import { Strategy } from "passport-local";

const app = express();
const port = 3000;
const saltRounds = 10;

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
    cookie: {
      maxAge: 1000 * 60 *24,
    }
  })
);

app.use(passport.initialize());
app.use(passport.session());

const db = new pg.Client({
  user: process.env.CLIENT_ID,
  host: process.env.CLIENT_HOST,
  database: process.env.CLIENT_DATABASE,
  password: process.env.CLIENT_PASSWORD,
  port: process.env.CLIENT_PORT,
});
db.connect();


app.get("/", (req, res) => {
  res.render("home.ejs");
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
});

app.get("/secrets", (req, res) => {
 //console.log(req.user);
  if(req.isAuthenticated()) {
    res.render("secrets.ejs");
  } else {
    res.redirect("/login");
  }
});

app.post("/register", async (req, res) => {
  const email= req.body.username;
  const password= req.body.password;

  try {
    const checkResult = await db.query("select * FROM users WHERE email = $1",[
      email,
    ])
  
    if(checkResult.rows.length > 0) {
      res.send("Email already exists. Try logging in.");
    } else {
      //password hashing
      bcrypt.hash(password, saltRounds, async (err, hash) => {
        if (err) {
          console.log("Error hashing password:", err);
        } else {
          console.log("hashed password", hash);
          const result = await db.query(
            "INSERT INTO users (email, password) VALUES ($1, $2) RETURNING *",
            [email, hash]
          );
          const user = result.rows[0];
          req.login(user, (err) => {
            console.log(err)
            res.redirect("/secrets");
          })
        }
      });
    }
  } catch (err) {
    console.log(err);
  }
});

app.post(
  "/login", 
  passport.authenticate("local", {
    successRedirect: "/secrets",
    failureRedirect: "/login",
  })
);

passport.use(new Strategy(async function verify(username, password, cb) {
  //console.log(username);

  try {
    const result = await db.query("select * FROM users WHERE email = $1",[
      username,
    ]);
    if (result.rows.length > 0) {
      console.log(result.rows);
      const user = result.rows[0];
      const storedHashedPassword = user.password;

      bcrypt.compare(password, storedHashedPassword, (err, result) => {
        if (err) {
          console.log("Error comparing passwords!", err);
        } else {
          if (result) {
            return cb(null, user)
          } else {
            return cb(null, false)
          }
        }
      });
    } else {
      return cb("user not found")
    }
  } catch (err) {
    return cb(err);
  }

}));

passport.serializeUser((user, cb) => {
  cb(null, user);    //save the data of the user who's loggedin to local storage
});

passport.deserializeUser((user, cb) => {
  cb(null, user);   //saves user info to local sessions & when you want to get hold of the user, it deserializes back
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});