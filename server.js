// server.js
import express from 'express';
import multer from 'multer';
import cors from 'cors';
import { createClient } from '@supabase/supabase-js';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import { v2 as cloudinary } from 'cloudinary';
import dotenv from 'dotenv';
import fs from 'fs';
import path from 'path';

dotenv.config();

const app = express();
app.use(cors({ origin: process.env.FRONTEND_URL, credentials: true }));
app.use(express.json());

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_ANON_KEY);

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

const upload = multer({ dest: '/tmp' });

const generateToken = (user) =>
  jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET, { expiresIn: '7d' });

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ error: 'Missing auth token' });
  const token = authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Invalid auth token' });

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Token invalid or expired' });
    req.user = user;
    next();
  });
};

const uploadImage = async (file) => {
  if (!file) return null;
  const result = await cloudinary.uploader.upload(file.path);
  fs.unlinkSync(file.path);
  return result.secure_url;
};

// Auth
app.post('/register', upload.single('image'), async (req, res) => {
  try {
    const { username, email, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const profile_image_url = await uploadImage(req.file);

    const { data, error } = await supabase
      .from('users')
      .insert([{ username, email, password: hashedPassword, profile_image_url }])
      .select()
      .single();

    if (error) return res.status(400).json({ error: error.message });

    const token = generateToken(data);
    res.json({ token, user: data });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const { data: user, error } = await supabase.from('users').select('*').eq('email', email).single();

    if (error || !user) return res.status(400).json({ error: 'Invalid email or password' });

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(400).json({ error: 'Invalid email or password' });

    const token = generateToken(user);
    res.json({ token, user });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/users/me', authenticateToken, upload.single('image'), async (req, res) => {
  try {
    const { username, email } = req.body;
    const profile_image_url = await uploadImage(req.file);
    const updateData = {};
    if (username) updateData.username = username;
    if (email) updateData.email = email;
    if (profile_image_url) updateData.profile_image_url = profile_image_url;

    const { data, error } = await supabase
      .from('users')
      .update(updateData)
      .eq('id', req.user.id)
      .select()
      .single();

    if (error) return res.status(400).json({ error: error.message });

    res.json(data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Posts
app.post('/posts', authenticateToken, upload.single('image'), async (req, res) => {
  try {
    const { title, content, category, tags } = req.body;
    const image_url = await uploadImage(req.file);
    const tagsArray = tags ? (Array.isArray(tags) ? tags : tags.split(',')) : [];

    const { data, error } = await supabase
      .from('posts')
      .insert([{ user_id: req.user.id, title, content, category, tags: tagsArray, image_url }])
      .select()
      .single();

    if (error) return res.status(400).json({ error: error.message });

    res.json(data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/posts', async (req, res) => {
  try {
    const { category, tags } = req.query;
    let query = supabase
      .from('posts')
      .select(`
        *,
        users:users!posts_user_id_fkey(username, profile_image_url),
        comments:comments(*),
        likes:likes(*)
      `)
      .order('created_at', { ascending: false });

    if (category) query = query.eq('category', category);
    if (tags) query = query.contains('tags', tags.split(','));

    const { data: posts, error } = await query;
    if (error) return res.status(500).json({ error: error.message });

    const postsWithCounts = posts.map(post => ({
      ...post,
      like_count: post.likes?.length || 0,
      comment_count: post.comments?.length || 0,
    }));

    res.json(postsWithCounts);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/posts/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const { data: post, error } = await supabase
      .from('posts')
      .select(`
        *,
        users:users!posts_user_id_fkey(username, profile_image_url),
        comments:comments(*, users(username, profile_image_url)),
        likes:likes(*)
      `)
      .eq('id', id)
      .single();

    if (error) return res.status(404).json({ error: 'Post not found' });

    const postWithCounts = {
      ...post,
      like_count: post.likes?.length || 0,
      comment_count: post.comments?.length || 0,
    };

    res.json(postWithCounts);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/posts/:id', authenticateToken, upload.single('image'), async (req, res) => {
  try {
    const { id } = req.params;
    const { title, content, category, tags } = req.body;
    const { data: existingPost, error: fetchError } = await supabase.from('posts').select('user_id').eq('id', id).single();
    if (fetchError) return res.status(400).json({ error: fetchError.message });
    if (existingPost.user_id !== req.user.id) return res.status(403).json({ error: 'Unauthorized' });

    const image_url = await uploadImage(req.file);
    const updateData = {};
    if (title) updateData.title = title;
    if (content) updateData.content = content;
    if (category) updateData.category = category;
    if (tags) updateData.tags = Array.isArray(tags) ? tags : tags.split(',');
    if (image_url) updateData.image_url = image_url;

    const { data, error } = await supabase.from('posts').update(updateData).eq('id', id).select().single();
    if (error) return res.status(400).json({ error: error.message });
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/posts/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { data: existingPost, error: fetchError } = await supabase.from('posts').select('user_id').eq('id', id).single();
    if (fetchError) return res.status(400).json({ error: fetchError.message });
    if (existingPost.user_id !== req.user.id) return res.status(403).json({ error: 'Unauthorized' });

    await supabase.from('comments').delete().eq('post_id', id);
    await supabase.from('likes').delete().eq('post_id', id);
    const { error } = await supabase.from('posts').delete().eq('id', id);
    if (error) return res.status(400).json({ error: error.message });

    res.json({ message: 'Post and related data deleted successfully' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Likes
app.post('/likes', authenticateToken, async (req, res) => {
  try {
    const { post_id } = req.body;
    if (!post_id) return res.status(400).json({ error: 'post_id required' });

    const { data: existingLike, error: fetchError } = await supabase
      .from('likes')
      .select('*')
      .eq('post_id', post_id)
      .eq('user_id', req.user.id)
      .single();

    if (!fetchError && existingLike) {
      await supabase.from('likes').delete().eq('id', existingLike.id);
      return res.json({ message: 'Unliked' });
    } else {
      const { data, error } = await supabase.from('likes').insert([{ post_id, user_id: req.user.id }]);
      if (error) return res.status(400).json({ error: error.message });
      return res.json({ message: 'Liked' });
    }
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Comments
app.get('/posts/:postId/comments', async (req, res) => {
  try {
    const { postId } = req.params;
    const { data, error } = await supabase
      .from('comments')
      .select('*, users(username, profile_image_url)')
      .eq('post_id', postId)
      .order('created_at', { ascending: true });

    if (error) return res.status(400).json({ error: error.message });
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/posts/:postId/comments', authenticateToken, async (req, res) => {
  try {
    const { postId } = req.params;
    const { content } = req.body;
    if (!content) return res.status(400).json({ error: 'Content is required' });

    const { data, error } = await supabase
      .from('comments')
      .insert([{ post_id: postId, user_id: req.user.id, content }])
      .select()
      .single();

    if (error) return res.status(400).json({ error: error.message });
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/comments/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { content } = req.body;
    if (!content) return res.status(400).json({ error: 'Content is required' });

    const { data: existingComment, error: fetchError } = await supabase
      .from('comments')
      .select('user_id')
      .eq('id', id)
      .single();

    if (fetchError) return res.status(400).json({ error: fetchError.message });
    if (existingComment.user_id !== req.user.id) return res.status(403).json({ error: 'Unauthorized' });

    const { data, error } = await supabase.from('comments').update({ content }).eq('id', id).select().single();
    if (error) return res.status(400).json({ error: error.message });
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/comments/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { data: existingComment, error: fetchError } = await supabase
      .from('comments')
      .select('user_id')
      .eq('id', id)
      .single();

    if (fetchError) return res.status(400).json({ error: fetchError.message });
    if (existingComment.user_id !== req.user.id) return res.status(403).json({ error: 'Unauthorized' });

    const { error } = await supabase.from('comments').delete().eq('id', id);
    if (error) return res.status(400).json({ error: error.message });

    res.json({ message: 'Comment deleted' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.listen(process.env.PORT || 3000, () => {
  console.log(`Server running on port ${process.env.PORT || 3000}`);
});
export default app;
