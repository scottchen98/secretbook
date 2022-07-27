require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const FacebookStrategy = require("passport-facebook").Strategy;

// The package mongoose-findorcreate implicitly passes two arguments(ID and Username) to the mongo server,
// When you tap into the first user, you store only the "ID" of the user, so the findorcreate package assigns null value to the username field.
// Again when you try to tap into second or multiple users, Since you already set a null value to the username field.
// MongoDB server allows only one entry of the null valued field. So It will throw an error.
const findOrCreate = require("mongoose-findorcreate");

const app = express();

// *************** General setup ******************
app.set("view engine", "ejs");
app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));

// *************** Session setup ******************
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
  })
);

// **************** Database **********************
mongoose.connect(
  `mongodb+srv://admin-scott:${process.env.ADMIN_SCOTT_PASSWORD}@cluster0.p1hfyol.mongodb.net/usersDB`
);

const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId: String,
  facebookId: String,
  secrets: Array,
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = mongoose.model("User", userSchema);

// *************** Passport authentication ******************
app.use(passport.initialize());
app.use(passport.session());

// Passport using passport-local-mongoose strategy
passport.use(User.createStrategy());

// Passport using passport-google-oauth20 strategy
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.CLIENT_ID,
      clientSecret: process.env.CLIENT_SECRET,
      callbackURL:
        "https://immense-ocean-88289.herokuapp.com/auth/google/secrets",
    },
    function (accessToken, refreshToken, profile, cb) {
      User.findOrCreate(
        { googleId: profile.id, email: profile._json.email },
        function (err, user) {
          return cb(err, user);
        }
      );
    }
  )
);

// Passport using passport-facebook strategy
passport.use(
  new FacebookStrategy(
    {
      clientID: process.env.APP_ID,
      clientSecret: process.env.APP_SECRET,
      callbackURL:
        "https://immense-ocean-88289.herokuapp.com/auth/facebook/secrets",
      // Obtain a user profile with specific fields
      profileFields: ["email"],
    },
    function (accessToken, refreshToken, profile, cb) {
      User.findOrCreate(
        { facebookId: profile.id, username: profile._json.email },
        function (err, user) {
          return cb(err, user);
        }
      );
    }
  )
);

// Serialize and deserialize user
// This function is used in conjunction with the `passport.authenticate()` method.
passport.serializeUser(function (user, cb) {
  process.nextTick(function () {
    return cb(null, {
      id: user.id,
      username: user.username,
      picture: user.picture,
    });
  });
});

// This function is used in conjunction with the `app.use(passport.session())` middleware.
passport.deserializeUser(function (user, cb) {
  process.nextTick(function () {
    return cb(null, user);
  });
});

// *************** Routes *********************
app.get("/", function (req, res) {
  res.render("home");
});

// Google authenticate requests
app.get(
  "/auth/google",
  passport.authenticate("google", { scope: ["profile", "email"] })
);

app.get(
  "/auth/google/secrets",
  passport.authenticate("google", { failureRedirect: "/login" }),
  function (req, res) {
    // Successful authentication, redirect to the secrets page.
    res.redirect("/secrets");
  }
);

// Facebook authenticate requests
// Facebook automatically grants public_profile and email of the user so {scope:[]} in this case can be omitted
app.get("/auth/facebook", passport.authenticate("facebook"));

app.get(
  "/auth/facebook/secrets",
  passport.authenticate("facebook", { failureRedirect: "/login" }),
  function (req, res) {
    // Successful authentication, redirect home.
    res.redirect("/secrets");
  }
);

app.get("/login", function (req, res) {
  res.render("login", { loginMessage: false });
});

app.post("/login", function (req, res) {
  passport.authenticate("local", function (err, user, info) {
    if (err) {
      console.log("Error", err);
    } else {
      // Login user if user is found
      if (user) {
        req.login(user, function (err) {
          if (err) {
            console.log("Error", err);
          }
          return res.redirect("/secrets");
        });
        // Otherwise, display a login message saying "Incorrect email or password"
      } else {
        console.log("Incorrect email or password.");
        res.render("login", { loginMessage: true });
      }
    }
  })(req, res);
});

app.get("/register", function (req, res) {
  res.render("register", { registerMessage: false });
});

app.post("/register", function (req, res) {
  User.find({ username: req.body.username }, function (err, email) {
    if (err) {
      console.log("Error", err);
    } else {
      // Display a register message if email already exists in the database
      if (email.length != 0) {
        console.log("This email is already registered!");
        res.render("register", { registerMessage: true });
      } else {
        // Otherwise, register this new user
        User.register(
          { username: req.body.username },
          req.body.password,
          function (err, user) {
            if (err) {
              console.log("Error", err);
              res.redirect("/register");
            } else {
              // passport.authenticate("local")(req, res, function () {
              //   res.redirect("/secrets");
              // });
              console.log("Registered a new user.");
              res.redirect("/login");
            }
          }
        );
      }
    }
  });
});

const secretContainer = [];
app.get("/secrets", function (req, res) {
  if (req.isAuthenticated()) {
    User.aggregate(
      [
        // Find all users with secrets only
        { $match: { secrets: { $ne: [] } } },
        // Return an array of secrets from each user
        { $group: { _id: null, secrets: { $push: "$secrets" } } },
      ],
      function (err, users) {
        if (!err) {
          // If no secrets stored in the database, just render the secrets page
          if (users.length === 0) {
            res.render("secrets", { usersSecrets: users });
          } else {
            const allSecrets = users[0].secrets;
            // Loop through all users secrets and add to secretContainer array
            for (let i = 0; i < allSecrets.length; i++) {
              allSecrets[i].forEach(function (secret) {
                if (
                  secretContainer.some(
                    (thisSecret) =>
                      thisSecret.secret == secret.secret &&
                      thisSecret.dateAdded == secret.dateAdded
                  )
                ) {
                } else {
                  secretContainer.push(secret);
                }
              });
            }

            // Sort array of secret objects in chronological order (newest secret at the beginning of array)
            secretContainer.sort(function (a, b) {
              return new Date(b.dateAdded) - new Date(a.dateAdded);
            });
            res.render("secrets", { usersSecrets: secretContainer });
          }
        }
      }
    );
  } else {
    res.redirect("/login");
  }
});

app.get("/my-secrets", function (req, res) {
  User.find({ _id: req.user.id }, function (err, me) {
    if (err) {
      console.log("Error", err);
    } else {
      const userSecretsArray = me[0].secrets;

      // Sort array of secret objects in chronological order (newest secret at the beginning of array)
      userSecretsArray.sort(function (a, b) {
        return new Date(b.dateAdded) - new Date(a.dateAdded);
      });
      res.render("mySecrets", { mySecrets: userSecretsArray });
    }
  });
});

app.post("/delete-secret", function (req, res) {
  const thisSecretDate = req.body.deleteSecret;

  // First find user by their id by going into req.user object
  User.findOne({ _id: req.user.id }, function (err, foundUser) {
    if (err) {
      console.log("Error", err);
    }

    // Get index of this specific secret in array that's located in database by comparing the date it was added
    const secretIndexFromDatabase = foundUser.secrets.findIndex((secret) => {
      return secret.dateAdded === thisSecretDate;
    });
    // Now we've acquired the index, splice method knows where to remove secret
    foundUser.secrets.splice(secretIndexFromDatabase, 1);

    // We also need to get index of this specific secret in secretContainer that was created above
    const secretIndexFromSecretContainer = secretContainer.findIndex(
      (secret) => {
        return secret.dateAdded === thisSecretDate;
      }
    );
    // Now specific secret can be removed since we know its position
    secretContainer.splice(secretIndexFromSecretContainer, 1);

    foundUser.save(function () {
      console.log("Deleted the user's secret.");
      res.redirect("/my-secrets");
    });
  });
});

app.get("/submit", function (req, res) {
  if (req.isAuthenticated()) {
    res.render("submit");
  } else {
    res.redirect("/login");
  }
});

app.post("/submit", function (req, res) {
  User.findById(req.user.id, function (err, user) {
    if (err) {
      console.log("Error", err);
    } else {
      if (user) {
        // Customize date with the following options
        options = {
          weekday: "long",
          year: "numeric",
          month: "long",
          day: "numeric",
          hour: "2-digit",
          minute: "2-digit",
          second: "2-digit",
        };

        // Add secret object to the secrets array
        user.secrets.push({
          secret: req.body.secret,
          dateAdded: new Date().toLocaleDateString("en-US", options),
        });
        user.save(function () {
          console.log("Updated user");
          res.redirect("/secrets");
        });
      } else {
        console.log("User not found.");
      }
    }
  });
});

app.get("/logout", function (req, res) {
  req.logout(function (err) {
    if (err) {
      console.log("Error", err);
    }
    res.redirect("/");
  });
});

let port = process.env.PORT;
if (port == null || port == "") {
  port = 3000;
}

app.listen(port, function () {
  console.log("Server has started successfully.");
});
