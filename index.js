const bcrypt = require("bcrypt");
const express = require("express");
const { UserModel, TodoModel } = require("./db");
const { auth, JWT_SECRET } = require("./auth");
const jwt = require("jsonwebtoken");
const mongoose = require("mongoose");
const { z } = require("zod");

mongoose.connect(
  ""
);

const app = express();
app.use(express.json());

app.post("/signup", async (req, res) => {
  const requireBody = z.object({
    email: z.string().min(3).max(100).email(),
    name: z.string().min(3).max(100),
    password: z
      .string()
      .min(5)
      .max(50)
      .regex(/[A-Z]/, "password must contain upper case letter")
      .regex(/[a-z]/, "password must contain lower case letter")
      .regex(
        /[!@#$%^&*()_<>?:]/,
        "password must contain any special character"
      ),
  });

  const parsedDataWithSuccess = requireBody.safeParse(req.body);

  if (!parsedDataWithSuccess.success) {
    res.json({
      message: "invalid format",
      error: parsedDataWithSuccess.error,
    });
    return;
  }

  const email = req.body.email;
  const name = req.body.name;
  const password = req.body.password;

  const hashedPassword = await bcrypt.hash(password, 5);
  console.log(hashedPassword);

  try {
    await UserModel.create({
      email: email,
      password: hashedPassword,
      name: name,
    });
  } catch (error) {
    return res.json({
      message: "user already exists",
    });
  }
  res.json({
    message: "You are signed up",
  });
});

app.post("/signin", async (req, res) => {
  const email = req.body.email;
  const password = req.body.password;

  const response = await UserModel.findOne({
    email: email,
  });

  if (!response) {
    res.status(403).json({
      message: "user does not exist",
    });
  }

  const passwordMatch = bcrypt.compare(password, response.password);

  if (passwordMatch) {
    const token = jwt.sign(
      {
        id: response._id.toString(),
      },
      JWT_SECRET
    );

    res.json({
      token,
    });
  } else {
    res.status(403).json({
      message: "Incorrect creds",
    });
  }
});

app.post("/todo", auth, async function (req, res) {
  const userId = req.userId;
  const title = req.body.title;
  const done = req.body.done;

  await TodoModel.create({
    userId,
    title,
    done,
  });

  res.json({
    message: "Todo created",
  });
});

app.get("/todos", auth, async function (req, res) {
  const userId = req.userId;

  const todos = await TodoModel.find({
    userId,
  });

  res.json({
    todos,
  });
});

app.listen(3000);
