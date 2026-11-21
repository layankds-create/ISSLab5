
import express from "express";
import { timingSafeEqual } from "node:crypto";
import sleep from "./utils/sleep.js";
import db from "./utils/db.js";
import {
  generateRandomness,
  KDF,
  checkPassword,
} from "./utils/crypto.js";

const router = express.Router();

function ensureCsrfToken(req) {
  if (!req.session.csrfToken) {
    req.session.csrfToken = generateRandomness();
  }

  return req.session.csrfToken;
}
function render(req, res, page, title, errorMsg = false, result = null) {
  res.render("layout/template", {
    page,
    title,
    loggedIn: req.session.loggedIn,
    account: req.session.account,
    errorMsg,
    result,
    csrfToken: ensureCsrfToken(req),
  });
}

router.get("/", (req, res) => {
  render(req, res, "index", "Bitbar Home");
});

router.post("/set_profile", (req, res) => {
  if (!req.session.loggedIn) {
    render(
      req,
      res,
      "login/form",
      "Login",
      "You must be logged in to use this feature!",
    );
    return;
  }

  const query = db.prepare(
    "UPDATE Users SET profile = ? WHERE username = ?;",
  );

  query.run(req.body.new_profile, req.session.account.username);
  req.session.account.profile = req.body.new_profile;

  render(req, res, "index", "Bitbar Home");
});

router.get("/login", (req, res) => {
  render(req, res, "login/form", "Login");
});

router.get("/get_login", (req, res) => {
  const query = db.prepare(
    "SELECT * FROM Users WHERE username == ?;",
  );
  const result = query.get(req.query.username);

  if (result && checkPassword(req.query.password, result)) {
    sleep(1000);

    req.session.loggedIn = true;
    req.session.account = result;

    render(req, res, "login/success", "Bitbar Home");
    return;
  }

  render(
    req,
    res,
    "login/form",
    "Login",
    "This username and password combination does not exist!",
  );
});

router.get("/register", (req, res) => {
  render(req, res, "register/form", "Register");
});

router.post("/post_register", (req, res) => {
  const query = db.prepare(
    "SELECT * FROM Users WHERE username == ?;",
  );
  const result = query.get(req.body.username);

  if (result) {
    render(
      req,
      res,
      "register/form",
      "Register",
      "This username already exists!",
    );
    return;
  }

  const salt = generateRandomness();
  const hashedPassword = KDF(req.body.password, salt);

  const insertQuery = db.prepare(
    `INSERT INTO Users
      (username, hashedPassword, salt, profile, bitbars)
     VALUES (?, ?, ?, ?, ?);`,
  );

  insertQuery.run(
    req.body.username,
    hashedPassword,
    salt,
    "",
    100,
  );

  req.session.loggedIn = true;
  req.session.account = {
    username: req.body.username,
    hashedPassword,
    salt,
    profile: "",
    bitbars: 100,
  };

  render(req, res, "register/success", "Bitbar Home");
});

router.get("/close", (req, res) => {
  if (!req.session.loggedIn) {
    render(
      req,
      res,
      "login/form",
      "Login",
      "You must be logged in to use this feature!",
    );
    return;
  }

  const query = db.prepare(
    "DELETE FROM Users WHERE username == ?;",
  );
  query.run(req.session.account.username);

  req.session.loggedIn = false;
  req.session.account = {};

  render(
    req,
    res,
    "index",
    "Bitbar Home",
    "Deleted account successfully!",
  );
});

router.get("/logout", (req, res) => {
  req.session.loggedIn = false;
  req.session.account = {};

  render(
    req,
    res,
    "index",
    "Bitbar Home",
    "Logged out successfully!",
  );
});

router.get("/profile", (req, res) => {
  if (req.query.username != null) {
    const query = db.prepare(
      "SELECT * FROM Users WHERE username == ?;",
    );
    const result = query.get(req.query.username);

    if (result) {
      render(
        req,
        res,
        "profile/view",
        "View Profile",
        false,
        result,
      );
    } else {
      render(
        req,
        res,
        "profile/view",
        "View Profile",
        `${req.query.username} does not exist!`,
        req.session.account,
      );
    }

    return;
  }

  render(
    req,
    res,
    "profile/view",
    "View Profile",
    false,
    req.session.account,
  );
});

router.get("/transfer", (req, res) => {
  if (!req.session.loggedIn) {
    render(
      req,
      res,
      "login/form",
      "Login",
      "You must be logged in to use this feature!",
    );
    return;
  }

  render(
    req,
    res,
    "transfer/form",
    "Transfer Bitbars",
    false,
    { receiver: null, amount: null },
  );
});

router.post("/post_transfer", (req, res) => {
  if (!req.session.loggedIn) {
    render(
      req,
      res,
      "login/form",
      "Login",
      "You must be logged in to use this feature!",
    );
    return;
  }

  const expectedToken = req.session.csrfToken;
  const submittedToken = req.body?.csrfToken;

  const validToken =
    typeof expectedToken === "string" &&
    typeof submittedToken === "string" &&
    /^[0-9a-f]{64}$/i.test(expectedToken) &&
    /^[0-9a-f]{64}$/i.test(submittedToken) &&
    timingSafeEqual(
      Buffer.from(submittedToken, "hex"),
      Buffer.from(expectedToken, "hex"),
    );

  if (!validToken) {
    return res.status(403).send("CSRF validation failed.");
  }

  if (req.body.destination_username === req.session.account.username) {
    render(
      req,
      res,
      "transfer/form",
      "Transfer Bitbars",
      "You cannot send money to yourself!",
      { receiver: null, amount: null },
    );
    return;
  }

  const query = db.prepare(
    "SELECT * FROM Users WHERE username == ?;",
  );

  const receiver = query.get(req.body.destination_username);

  if (receiver) {
    const amount = Number(req.body.quantity);
    const sender = query.get(req.session.account.username);

    if (
      !sender ||
      !Number.isSafeInteger(amount) ||
      amount <= 0 ||
      amount > sender.bitbars ||
      !Number.isSafeInteger(receiver.bitbars + amount)
    ) {
      render(
        req,
        res,
        "transfer/form",
        "Transfer Bitbars",
        "Invalid transfer amount!",
        { receiver: null, amount: null },
      );
      return;
    }

    const senderNewBal = sender.bitbars - amount;
    const receiverNewBal = receiver.bitbars + amount;

    const updateQuery = db.prepare(
      "UPDATE Users SET bitbars = ? WHERE username == ?;",
    );

    const transfer = db.transaction(() => {
      updateQuery.run(senderNewBal, sender.username);
      updateQuery.run(receiverNewBal, receiver.username);
    });

    transfer();

    req.session.account.bitbars = senderNewBal;

    render(
      req,
      res,
      "transfer/success",
      "Transfer Complete",
      false,
      { receiver, amount },
    );

    return;
  }

  let q = req.body.destination_username;
  if (q == null) q = "";

  let oldQ;
  while (q !== oldQ) {
    oldQ = q;
    q = q.replace(/script|SCRIPT|img|IMG/g, "");
  }

  render(
    req,
    res,
    "transfer/form",
    "Transfer Bitbars",
    `User ${q} does not exist!`,
    { receiver: null, amount: null },
  );
});

// db dump endpoint (DO NOT CHANGE)
router.get("/db_dump", (_, res) => {
  res.setHeader("Content-Type", "application/json");
  const query = db.prepare(`SELECT * FROM Users;`);
  const result = query.all();
  res.send(JSON.stringify(result, null, 2));
});

export default router;