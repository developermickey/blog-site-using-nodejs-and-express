const express = require("express");
const mongoose = require("mongoose");
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const multer = require("multer");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const path = require("path");

const app = express();

// Middleware
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static("public"));
app.set("view engine", "ejs");

// Multer setup for image uploads
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, "public/uploads");
  },
  filename: function (req, file, cb) {
    cb(null, Date.now() + "-" + file.originalname);
  },
});
const upload = multer({ storage: storage });

// MongoDB connection
mongoose.connect("mongodb://localhost:27017/blogss", {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

// Models
const User = mongoose.model(
  "User",
  new mongoose.Schema({
    fullName: String,
    email: String,
    username: String,
    password: String,
    profileImage: String,
  })
);

const Blog = mongoose.model(
  "Blog",
  new mongoose.Schema({
    title: String,
    content: String,
    image: String,
    author: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
    created_at: { type: Date, default: Date.now },
  })
);

// Middleware to check authentication and set loggedIn variable
app.use((req, res, next) => {
  const token = req.cookies.token;
  if (token) {
    try {
      const decoded = jwt.verify(token, "secret");
      req.user = decoded;
      res.locals.loggedIn = true;
    } catch (err) {
      res.locals.loggedIn = false;
    }
  } else {
    res.locals.loggedIn = false;
  }
  next();
});

// Auth Middleware
const authMiddleware = (req, res, next) => {
  const token = req.cookies.token;
  if (!token) {
    return res.redirect("/login"); // Redirect to login if token is not present
  }
  try {
    const decoded = jwt.verify(token, "secret");
    req.user = decoded;
    next(); // Proceed to the next middleware if token is valid
  } catch (err) {
    res.redirect("/login"); // Redirect to login if token is invalid
  }
};

// Routes
app.get("/", async (req, res) => {
  try {
    const blogs = await Blog.find()
      .sort({ created_at: -1 })
      .populate("author", "username");

    res.render("index", {
      title: "Home",
      blogs,
      loggedIn: res.locals.loggedIn,
      user: req.user, // Pass req.user to access user information in EJS
    });
  } catch (err) {
    console.error(err);
    res.status(500).send("Server Error");
  }
});

// Register route
app.get("/register", (req, res) => {
  // Check if user is already logged in
  if (res.locals.loggedIn) {
    return res.redirect("/profile"); // Redirect to profile if logged in
  }
  res.render("register", { title: "Sign Up" });
});

app.post("/register", upload.single("profileImage"), async (req, res) => {
  const { fullName, email, username, password } = req.body;
  const profileImage = req.file ? `/uploads/${req.file.filename}` : null;

  try {
    if (!fullName || !email || !username || !password || !profileImage) {
      return res.status(400).send("All fields are required");
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({
      fullName,
      email,
      username,
      password: hashedPassword,
      profileImage,
    });

    await user.save();
    res.redirect("/login");
  } catch (err) {
    console.error(err);
    res.status(500).send("Server Error");
  }
});

// Login route
app.get("/login", (req, res) => {
  // Check if user is already logged in
  if (res.locals.loggedIn) {
    return res.redirect("/profile"); // Redirect to profile if logged in
  }
  res.render("login", { title: "Login" });
});

app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  try {
    const user = await User.findOne({ username });

    if (!user) {
      return res.status(400).send("Invalid username or password");
    }

    const isMatch = await bcrypt.compare(password, user.password);

    if (isMatch) {
      const token = jwt.sign({ id: user._id }, "secret", { expiresIn: "1h" });
      res.cookie("token", token, { httpOnly: true });
      res.redirect("/profile"); // Redirect to profile on successful login
    } else {
      res.status(400).send("Invalid username or password");
    }
  } catch (err) {
    console.error(err);
    res.status(500).send("Server Error");
  }
});

// Logout route
app.get("/logout", (req, res) => {
  res.clearCookie("token");
  res.redirect("/");
});

// Profile route
app.get("/profile", authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select("-password"); // Exclude password from query result
    if (!user) {
      return res.status(404).send("User not found");
    }
    res.render("profile", { title: "Profile", user });
  } catch (err) {
    console.error(err);
    res.status(500).send("Server Error");
  }
});

// Update profile route
app.post("/profile", authMiddleware, async (req, res) => {
  const { fullName, email, username } = req.body;

  try {
    const user = await User.findById(req.user.id);
    if (!user) {
      return res.status(404).send("User not found");
    }

    user.fullName = fullName;
    user.email = email;
    user.username = username;
    await user.save();

    res.redirect("/profile");
  } catch (err) {
    console.error(err);
    res.status(500).send("Server Error");
  }
});

// Start server
app.listen(3000, () => {
  console.log("Server is running on port 3000");
});
