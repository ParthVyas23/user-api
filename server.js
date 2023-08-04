require("dotenv").config();

const express = require("express");
const app = express();
const cors = require("cors");

const userService = require("./user-service.js");
const passport = require("passport");
const passportJWT = require("passport-jwt");

const JwtStrategy = passportJWT.Strategy;
const ExtractJwt = passportJWT.ExtractJwt;
const jwt = require("jsonwebtoken");

const jwtStrategyOptions = {
  jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
  secretOrKey: process.env.JWT_SECRET,
};

const HTTP_PORT = process.env.PORT || 8080;

passport.use(
  new JwtStrategy(jwtStrategyOptions, async (jwtPayload, done) => {
    await userService.checkJWT(
      jwtPayload.userName,
      jwtPayload.id,
      (err, user) => {
        if (err) {
          return done(err, false);
        }
        if (user) {
          return done(null, user);
        } else {
          return done(null, false);
        }
      }
    );
  })
);

app.use(express.json());
app.use(cors());

app.post("/api/user/register", (req, res) => {
  userService
    .registerUser(req.body)
    .then((msg) => {
      res.json({ message: msg });
    })
    .catch((msg) => {
      res.status(422).json({ message: msg });
    });
});

app.post("/api/user/login", (req, res) => {
  const { userName, password } = req.body;

  userService
    .checkUser(req.body)
    .then((user) => {
      const payload = { id: user._id, userName: user.userName };

      jwt.sign(payload, process.env.JWT_SECRET, (err, token) => {
        if (err) {
          return res
            .status(500)
            .json({ message: "Failed to generate JWT token" });
        }

        return res
          .status(200)
          .json({ message: "Login successful", token: token });
      });
    })
    .catch((err) => {
      return res.status(401).json({ message: "Invalid credentials" });
    });
});

app.get(
  "/api/user/favourites",
  passport.authenticate("jwt", { session: false }),
  (req, res) => {
    userService
      .getFavourites(req.user.id)
      .then((data) => {
        res.json(data);
      })
      .catch((msg) => {
        res.status(422).json({ error: msg });
      });
  }
);

app.put(
  "/api/user/favourites/:id",
  passport.authenticate("jwt", { session: false }),
  (req, res) => {
    userService
      .addFavourite(req.user.id, req.params.id)
      .then((data) => {
        res.json(data);
      })
      .catch((msg) => {
        res.status(422).json({ error: msg });
      });
  }
);

app.delete(
  "/api/user/favourites/:id",
  passport.authenticate("jwt", { session: false }),
  (req, res) => {
    userService
      .removeFavourite(req.user.id, req.params.id)
      .then((data) => {
        res.json(data);
      })
      .catch((msg) => {
        res.status(422).json({ error: msg });
      });
  }
);

app.get(
  "/api/user/history",
  passport.authenticate("jwt", { session: false }),
  (req, res) => {
    userService
      .getHistory(req.user.id)
      .then((data) => {
        res.json(data);
      })
      .catch((msg) => {
        res.status(422).json({ error: msg });
      });
  }
);

app.put(
  "/api/user/history/:id",
  passport.authenticate("jwt", { session: false }),
  (req, res) => {
    userService
      .addHistory(req.user.id, req.params.id)
      .then((data) => {
        res.json(data);
      })
      .catch((msg) => {
        res.status(422).json({ error: msg });
      });
  }
);

app.delete(
  "/api/user/history/:id",
  passport.authenticate("jwt", { session: false }),
  (req, res) => {
    userService
      .removeHistory(req.user.id, req.params.id)
      .then((data) => {
        res.json(data);
      })
      .catch((msg) => {
        res.status(422).json({ error: msg });
      });
  }
);

userService
  .connect()
  .then(() => {
    app.listen(HTTP_PORT, () => {
      console.log("API listening on: " + HTTP_PORT);
    });
  })
  .catch((err) => {
    console.log("unable to start the server: " + err);
    process.exit();
  });
