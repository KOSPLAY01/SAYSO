import express from "express";
import bodyParser from "body-parser";
import bcrypt from "bcrypt";
import session from "express-session";
import passport from "passport";
import { Strategy as LocalStrategy } from "passport-local";
import { Strategy as GoogleStrategy } from "passport-google-oauth2";
import { createClient } from "@supabase/supabase-js";
import dotenv from "dotenv";
import cors from "cors";
import multer from "multer";
import { v2 as cloudinaryV2 } from "cloudinary";
import { CloudinaryStorage } from "multer-storage-cloudinary";

dotenv.config();

const app = express();
const port = process.env.PORT || 3000;
const saltRounds = 10;

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_ANON_KEY);

// Cloudinary setup
cloudinaryV2.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

const storageProfilePic = new CloudinaryStorage({
  cloudinary: cloudinaryV2,
  params: {
    folder: "profile_pics",
    allowed_formats: ["jpg", "jpeg", "png"]
  }
});

const storagePostImage = new CloudinaryStorage({
  cloudinary: cloudinaryV2,
  params: {
    folder: "post_images",
    allowed_formats: ["jpg", "jpeg", "png"]
  }
});

const uploadProfilePic = multer({ storage: storageProfilePic });
const uploadPostImage = multer({ storage: storagePostImage });

app.use(cors({
  origin: process.env.FRONTEND_URL,
  credentials: true
}));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.json());

app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: true
}));

app.use(passport.initialize());
app.use(passport.session());

// Passport local strategy
passport.use("local", new LocalStrategy({
  usernameField: "email",
  passwordField: "password"
}, async (email, password, done) => {
  const { data: user, error } = await supabase
    .from("users")
    .select("*")
    .eq("email", email)
    .single();

  if (error || !user) return done(null, false, { message: "User not found" });

  const match = await bcrypt.compare(password, user.password);
  if (!match) return done(null, false, { message: "Incorrect password" });

  return done(null, user);
}));

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  const { data: user, error } = await supabase
    .from("users")
    .select("*")
    .eq("id", id)
    .single();
  done(error, user);
});

// Google OAuth Strategy
passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: process.env.GOOGLE_CALLBACK_URL,
  passReqToCallback: true
}, async (req, accessToken, refreshToken, profile, done) => {
  try {
    const email = profile.email;
    const fullname = profile.displayName;
    const username = profile.given_name.toLowerCase() + "_" + profile.id.slice(0, 5);
    const image_url = profile.picture;

    const { data: existingUser, error } = await supabase
      .from("users")
      .select("*")
      .eq("email", email)
      .single();

    if (error && error.code !== "PGRST116") return done(error);

    if (!existingUser) {
      const { data: newUser, error: insertError } = await supabase
        .from("users")
        .insert([{ email, password: "google", fullname, username, image_url }])
        .select()
        .single();
      if (insertError) return done(insertError);
      return done(null, newUser);
    } else {
      return done(null, existingUser);
    }
  } catch (err) {
    return done(err);
  }
}));

// Middleware to check authentication
const isAuth = (req, res, next) => {
  if (!req.isAuthenticated()) return res.status(401).json({ message: "Unauthorized" });
  next();
};

// Routes
app.get("/", (req, res) => {
  res.json({ message: "Welcome to the SAYSO!" });
});

// Register user with profile pic upload
app.post("/api/register", uploadProfilePic.single("profilePic"), async (req, res) => {
  const { email, password, fullname, username, bio } = req.body;
  const profilePicUrl = req.file?.path;

  const { data: existingUser } = await supabase
    .from("users")
    .select("*")
    .eq("email", email)
    .single();

  if (existingUser) return res.status(400).json({ message: "User already exists" });

  const hashedPassword = await bcrypt.hash(password, saltRounds);

  const { data: newUser, error } = await supabase
    .from("users")
    .insert([{ email, password: hashedPassword, fullname, username, bio, image_url: profilePicUrl }])
    .select()
    .single();

  if (error) return res.status(500).json({ message: "Registration failed", error });

  req.login(newUser, (err) => {
    if (err) return res.status(500).json({ message: "Login after registration failed" });
    res.json(newUser);
  });
});

// Update user profile (except password), with optional profile pic upload
app.put("/api/user", isAuth, uploadProfilePic.single("profilePic"), async (req, res) => {
  const { fullname, username, email, bio } = req.body;
  const profilePicUrl = req.file?.path;
  const userId = req.user.id;

  // Build update object dynamically
  const updateData = {};
  if (fullname) updateData.fullname = fullname;
  if (username) updateData.username = username;
  if (email) updateData.email = email;
  if (bio) updateData.bio = bio;
  if (profilePicUrl) updateData.image_url = profilePicUrl;

  if (Object.keys(updateData).length === 0) {
    return res.status(400).json({ message: "No fields to update" });
  }

  const { data, error } = await supabase
    .from("users")
    .update(updateData)
    .eq("id", userId)
    .select()
    .single();

  if (error) return res.status(500).json({ message: "Update failed", error });

  res.json(data);
});

// Login user
app.post("/api/login", (req, res, next) => {
  passport.authenticate("local", (err, user, info) => {
    if (err) return res.status(500).json({ message: "Login error", err });
    if (!user) return res.status(401).json({ message: info.message });

    req.login(user, (err) => {
      if (err) return res.status(500).json({ message: "Login failed", err });
      res.json(user);
    });
  })(req, res, next);
});

// User Profile
app.get("/api/profile", (req, res) => {
  if (!req.isAuthenticated()) return res.status(401).json({ message: "Unauthorized" });
  res.json(req.user);
});

// Logout
app.post("/api/logout", (req, res) => {
  req.logout((err) => {
    if (err) return res.status(500).json({ message: "Logout failed" });
    res.json({ message: "Logged out" });
  });
});

// Google OAuth
app.get("/auth/google", passport.authenticate("google", {
  scope: ["profile", "email"]
}));

app.get("/auth/google/callback", passport.authenticate("google", {
  failureRedirect: `${process.env.FRONTEND_URL}/login`
}), (req, res) => {
  res.redirect(`${process.env.FRONTEND_URL}/dashboard`);
});

// Create a new blog post with image upload
app.post("/api/posts", isAuth, uploadPostImage.single("image"), async (req, res) => {
  const { title, content, category, tags } = req.body;
  const imageUrl = req.file?.path;
  const user_id = req.user.id;

  if (!title || !content) return res.status(400).json({ message: "Title and content are required" });

  const tagsArray = typeof tags === "string" ? tags.split(",").map(t => t.trim()) : tags;

  const { data, error } = await supabase
    .from("blog_posts")
    .insert([{ title, content, user_id, category, tags: tagsArray, image_url: imageUrl }])
    .select()
    .single();

  if (error) return res.status(500).json({ message: "Failed to create post", error });
  res.json(data);
});

// Get all posts with optional filter by category and tag
app.get("/api/posts", async (req, res) => {
  const { category, tag } = req.query;

  let query = supabase
    .from("blog_posts")
    .select("*, users!inner(username, image_url)")
    .order("created_at", { ascending: false });

  if (category) {
    query = query.eq("category", category);
  }

  if (tag) {
    query = query.contains("tags", [tag]);
  }

  const { data, error } = await query;

  if (error) return res.status(500).json({ error });
  res.json(data);
});

// Get single post by id
app.get("/api/posts/:id", async (req, res) => {
  const { id } = req.params;
  const { data, error } = await supabase
    .from("blog_posts")
    .select("*, users!inner(username, image_url)")
    .eq("id", id)
    .single();

  if (error || !data) return res.status(404).json({ message: "Post not found" });
  res.json(data);
});

// Update a post (only by creator)
app.put("/api/posts/:id", isAuth, uploadPostImage.single("image"), async (req, res) => {
  const { id } = req.params;
  const { title, content, category, tags } = req.body;
  const imageUrl = req.file?.path;

  const { data: existingPost, error: fetchError } = await supabase
    .from("blog_posts")
    .select("*")
    .eq("id", id)
    .single();

  if (fetchError || !existingPost) return res.status(404).json({ message: "Post not found" });
  if (existingPost.user_id !== req.user.id) return res.status(403).json({ message: "Forbidden" });

  // Prepare update data
  const updateData = {};
  if (title) updateData.title = title;
  if (content) updateData.content = content;
  if (category) updateData.category = category;
  if (tags) {
    updateData.tags = typeof tags === "string" ? tags.split(",").map(t => t.trim()) : tags;
  }
  if (imageUrl) updateData.image_url = imageUrl;

  const { data, error } = await supabase
    .from("blog_posts")
    .update(updateData)
    .eq("id", id)
    .select()
    .single();

  if (error) return res.status(500).json({ message: "Update failed", error });
  res.json(data);
});

// Delete a post (only by creator)
app.delete("/api/posts/:id", isAuth, async (req, res) => {
  const { id } = req.params;

  const { data: existingPost, error: fetchError } = await supabase
    .from("blog_posts")
    .select("*")
    .eq("id", id)
    .single();

  if (fetchError || !existingPost) return res.status(404).json({ message: "Post not found" });
  if (existingPost.user_id !== req.user.id) return res.status(403).json({ message: "Forbidden" });

  const { error } = await supabase.from("blog_posts").delete().eq("id", id);

  if (error) return res.status(500).json({ message: "Delete failed", error });
  res.json({ message: "Post deleted" });
});

// Add comment to a post (authenticated)
app.post("/api/posts/:postId/comments", isAuth, async (req, res) => {
  const { postId } = req.params;
  const { content } = req.body;
  const user_id = req.user.id;

  if (!content) return res.status(400).json({ message: "Content is required" });

  // Check post exists
  const { data: post, error: postError } = await supabase
    .from("blog_posts")
    .select("id")
    .eq("id", postId)
    .single();

  if (postError || !post) return res.status(404).json({ message: "Post not found" });

  const { data, error } = await supabase
    .from("comments")
    .insert([{ content, post_id: postId, user_id }])
    .select()
    .single();

  if (error) return res.status(500).json({ message: "Failed to add comment", error });
  res.json(data);
});

// Get comments for a post (public)
app.get("/api/posts/:postId/comments", async (req, res) => {
  const { postId } = req.params;

  const { data, error } = await supabase
    .from("comments")
    .select("*, users!inner(username, image_url)")
    .eq("post_id", postId)
    .order("created_at", { ascending: true });

  if (error) return res.status(500).json({ message: "Failed to fetch comments", error });
  res.json(data);
});

// Edit comment (only by creator)
app.put("/api/comments/:commentId", isAuth, async (req, res) => {
  const { commentId } = req.params;
  const { content } = req.body;
  const user_id = req.user.id;

  if (!content) return res.status(400).json({ message: "Content is required" });

  const { data: existingComment, error: fetchError } = await supabase
    .from("comments")
    .select("*")
    .eq("id", commentId)
    .single();

  if (fetchError || !existingComment) return res.status(404).json({ message: "Comment not found" });
  if (existingComment.user_id !== user_id) return res.status(403).json({ message: "Forbidden" });

  const { data, error } = await supabase
    .from("comments")
    .update({ content })
    .eq("id", commentId)
    .select()
    .single();

  if (error) return res.status(500).json({ message: "Failed to update comment", error });
  res.json(data);
});

// Delete comment (only by creator)
app.delete("/api/comments/:commentId", isAuth, async (req, res) => {
  const { commentId } = req.params;
  const user_id = req.user.id;

  const { data: existingComment, error: fetchError } = await supabase
    .from("comments")
    .select("*")
    .eq("id", commentId)
    .single();

  if (fetchError || !existingComment) return res.status(404).json({ message: "Comment not found" });
  if (existingComment.user_id !== user_id) return res.status(403).json({ message: "Forbidden" });

  const { error } = await supabase
    .from("comments")
    .delete()
    .eq("id", commentId);

  if (error) return res.status(500).json({ message: "Failed to delete comment", error });
  res.json({ message: "Comment deleted" });
});


app.listen(port, () => {
console.log(`Server listening on port ${port}`);
});