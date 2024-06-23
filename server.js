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
    return res.redirect("/login");
  }
  try {
    const decoded = jwt.verify(token, "secret");
    req.user = decoded;
    next();
  } catch (err) {
    res.redirect("/login");
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

app.get("/register", (req, res) => {
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

app.get("/login", (req, res) => {
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
      res.redirect("/");
    } else {
      res.status(400).send("Invalid username or password");
    }
  } catch (err) {
    console.error(err);
    res.status(500).send("Server Error");
  }
});

app.get("/logout", (req, res) => {
  res.clearCookie("token");
  res.redirect("/");
});

app.get("/create", authMiddleware, (req, res) => {
  res.render("create", { title: "Create Blog" });
});

app.post(
  "/create",
  authMiddleware,
  upload.single("image"),
  async (req, res) => {
    const { title, content } = req.body;
    const blog = new Blog({
      title,
      content,
      image: req.file ? `/uploads/${req.file.filename}` : null,
      author: req.user.id,
    });

    await blog.save();
    res.redirect("/");
  }
);

app.get("/edit/:id", authMiddleware, async (req, res) => {
  try {
    if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
      return res.status(400).send("Invalid Blog ID");
    }

    const blog = await Blog.findById(req.params.id);
    if (!blog) {
      return res.status(404).send("Blog not found");
    }

    if (!blog.author.equals(req.user.id)) {
      return res.status(403).send("Unauthorized access");
    }

    res.render("edit", { title: "Edit Blog", blog });
  } catch (err) {
    console.error(err);
    res.status(500).send("Server Error");
  }
});

app.post(
  "/edit/:id",
  authMiddleware,
  upload.single("image"),
  async (req, res) => {
    try {
      if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
        return res.status(400).send("Invalid Blog ID");
      }

      const { title, content } = req.body;
      let image = req.file ? `/uploads/${req.file.filename}` : null;

      const updatedBlog = await Blog.findByIdAndUpdate(
        req.params.id,
        {
          title,
          content,
          image,
        },
        { new: true }
      );

      if (!updatedBlog) {
        return res.status(404).send("Blog not found");
      }

      if (!updatedBlog.author.equals(req.user.id)) {
        return res.status(403).send("Unauthorized access");
      }

      res.redirect("/");
    } catch (err) {
      console.error(err);
      res.status(500).send("Server Error");
    }
  }
);

// Profile route
app.get("/profile", authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select("-password"); // Exclude password from query result
    if (!user) {
      return res.status(404).send("User not found");
    }
    res.render("profile", { title: "Prolile", user });
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
