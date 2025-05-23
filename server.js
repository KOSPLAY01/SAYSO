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
import { createServer } from 'http';
import { Server } from 'socket.io';


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

// Socket.io setup
const httpServer = createServer(app);
const io = new Server(httpServer, {
  cors: {
    origin:process.env.FRONTEND_URL , // or your frontend URL
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    credentials: true
  }
});

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.json());

app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: true,
   cookie: {
    sameSite: "none",  // ✅ allow cross-origin cookies
    secure: true       // ✅ required for 'SameSite: none' to work (must be HTTPS)
  }
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

// track online users
const onlineUsers = new Map();

io.on('connection', (socket) => {
  console.log('User connected:', socket.id);

  socket.on('register', (userId) => {
    onlineUsers.set(userId, socket.id);
  });

  socket.on('disconnect', () => {
    for (let [userId, socketId] of onlineUsers.entries()) {
      if (socketId === socket.id) {
        onlineUsers.delete(userId);
        break;
      }
    }
    console.log('User disconnected:', socket.id);
  });
});


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

app.get("/api/profile", async (req, res) => {
  if (!req.isAuthenticated()) return res.status(401).json({ message: "Unauthorized" });

  try {
    const user = req.user;

    // Fetch user's posts
    const { data: posts, error: postsError } = await supabase
      .from("posts")
      .select("*, comments(*), likes(count)")
      .eq("user_id", user.id); // or "author_id", depending on your schema

    if (postsError) {
      console.error("Error fetching user posts:", postsError.message);
      return res.status(500).json({ message: "Failed to fetch user posts" });
    }

    // Format posts with comment count and like count
    const formattedPosts = posts.map(post => ({
      ...post,
      comment_count: post.comments?.length || 0,
      like_count: post.likes?.[0]?.count || 0,
    }));

    res.json({
      user,
      posts: formattedPosts,
    });
  } catch (err) {
    console.error("Server error:", err);
    res.status(500).json({ message: "Server error" });
  }
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
    .insert([{ title, content, user_id, category, tags: tagsArray, image_url: imageUrl, like_count: 0, comment_count: 0 }])
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

// Delete a post (only by creator) and all related comments and likes
app.delete("/api/posts/:id", isAuth, async (req, res) => {
  const { id } = req.params;

  const { data: post, error: postError } = await supabase
    .from("blog_posts")
    .select("*")
    .eq("id", id)
    .single();

  if (postError || !post) return res.status(404).json({ message: "Post not found" });
  if (post.user_id !== req.user.id) return res.status(403).json({ message: "Forbidden" });

  // Delete likes related to this post
  await supabase.from("likes").delete().eq("post_id", id);
  // Delete comments related to this post
  await supabase.from("comments").delete().eq("post_id", id);
  // Delete post
  const { error: delError } = await supabase.from("blog_posts").delete().eq("id", id);

  if (delError) return res.status(500).json({ message: "Delete failed", error: delError });

  res.json({ message: "Post deleted" });
});

// Like or Unlike a post (toggle)
app.post("/api/posts/:id/like", isAuth, async (req, res) => {
  const post_id = req.params.id;
  const user_id = req.user.id;

  // Check if post exists
  const { data: post, error: postError } = await supabase
    .from("blog_posts")
    .select("id, user_id, like_count") // include owner ID
    .eq("id", post_id)
    .single();

  if (postError || !post) return res.status(404).json({ message: "Post not found" });

  // Check if user already liked this post
  const { data: existingLike } = await supabase
    .from("likes")
    .select("*")
    .eq("post_id", post_id)
    .eq("user_id", user_id)
    .single();

  if (existingLike) {
    // Unlike
    const { error } = await supabase
      .from("likes")
      .delete()
      .eq("post_id", post_id)
      .eq("user_id", user_id);

    if (error) return res.status(500).json({ message: "Failed to unlike post", error });

    await supabase.rpc("decrement_like_count", { p_id: post_id });

    return res.json({ liked: false });
  } else {
    // Like
    const { error } = await supabase
      .from("likes")
      .insert([{ post_id, user_id }]);

    if (error) return res.status(500).json({ message: "Failed to like post", error });

    await supabase.rpc("increment_like_count", { p_id: post_id });

    // Notify post owner if not the liker
    if (post.user_id !== user_id) {
      const receiverSocketId = onlineUsers.get(post.user_id);
      const senderUsername = req.user.username;

      if (receiverSocketId) {
        io.to(receiverSocketId).emit("notification", {
          message: `${senderUsername} liked your post`,
          type: "like",
          postId: post_id
        });
      }
    }

    return res.json({ liked: true });
  }
});

// Add comment to a post
app.post("/api/posts/:id/comments", isAuth, async (req, res) => {
  const post_id = req.params.id;
  const user_id = req.user.id;
  const { content } = req.body;

  if (!content) return res.status(400).json({ message: "Content is required" });

  const { data: post } = await supabase
    .from("blog_posts")
    .select("id, user_id") // include post owner
    .eq("id", post_id)
    .single();

  if (!post) return res.status(404).json({ message: "Post not found" });

  const { data: comment, error } = await supabase
    .from("comments")
    .insert([{ post_id, user_id, content }])
    .select()
    .single();

  if (error) return res.status(500).json({ message: "Failed to add comment", error });

  await supabase.rpc("increment_comment_count", { p_id: post_id });

  // Notify post owner if not the commenter
  if (post.user_id !== user_id) {
    const receiverSocketId = onlineUsers.get(post.user_id);
    const senderUsername = req.user.username;

    if (receiverSocketId) {
      io.to(receiverSocketId).emit("notification", {
        message: `${senderUsername} commented on your post`,
        type: "comment",
        postId: post_id
      });
    }
  }

  res.json(comment);
});

// Edit comment (only comment owner)
app.put("/api/comments/:id", isAuth, async (req, res) => {
  const comment_id = req.params.id;
  const user_id = req.user.id;
  const { content } = req.body;

  if (!content) return res.status(400).json({ message: "Content is required" });

  const { data: comment, error: fetchError } = await supabase
    .from("comments")
    .select("*")
    .eq("id", comment_id)
    .single();

  if (fetchError || !comment) return res.status(404).json({ message: "Comment not found" });
  if (comment.user_id !== user_id) return res.status(403).json({ message: "Forbidden" });

  const { data, error } = await supabase
    .from("comments")
    .update({ content })
    .eq("id", comment_id)
    .select()
    .single();

  if (error) return res.status(500).json({ message: "Failed to update comment", error });

  res.json(data);
});

// Delete comment (only comment owner)
app.delete("/api/comments/:id", isAuth, async (req, res) => {
  const comment_id = req.params.id;
  const user_id = req.user.id;

  const { data: comment, error: fetchError } = await supabase
    .from("comments")
    .select("*")
    .eq("id", comment_id)
    .single();

  if (fetchError || !comment) return res.status(404).json({ message: "Comment not found" });
  if (comment.user_id !== user_id) return res.status(403).json({ message: "Forbidden" });

  const { error } = await supabase
    .from("comments")
    .delete()
    .eq("id", comment_id);

  if (error) return res.status(500).json({ message: "Failed to delete comment", error });

  // Decrement comment_count safely
  await supabase.rpc("decrement_comment_count", { p_id: comment.post_id });

  res.json({ message: "Comment deleted" });
});

// Get all comments for a post
app.get("/api/posts/:id/comments", async (req, res) => {
  const post_id = req.params.id;

  const { data, error } = await supabase
    .from("comments")
    .select("*, users!inner(username, image_url)")
    .eq("post_id", post_id)
    .order("created_at", { ascending: true });

  if (error) return res.status(500).json({ message: "Failed to get comments", error });

  res.json(data);
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
