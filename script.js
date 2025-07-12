const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
require('dotenv').config(); // Added for environment variables

const app = express();
app.use(express.json());
app.use(cors({ origin: process.env.CORS_ORIGIN || '*' })); // Configurable CORS

// MongoDB Connection
mongoose.connect(process.env.MONGO_URI || 'mongodb://localhost/nutrition-tracker')
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => {
    console.error('MongoDB connection error:', err);
    process.exit(1); // Exit if connection fails
  });

// User Schema
const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
});
const User = mongoose.model('User', userSchema);

// Pantry Schema
const pantrySchema = new mongoose.Schema({
  userId: { type: String, required: true },
  ingredients: [{ name: String, quantity: Number }],
});
const Pantry = mongoose.model('Pantry', pantrySchema);

// Recipe Schema
const recipeSchema = new mongoose.Schema({
  name: String,
  ingredients: [String],
  instructions: [String],
});
const Recipe = mongoose.model('Recipe', recipeSchema);

// Middleware to verify JWT
const authMiddleware = (req, res, next) => {
  const authHeader = req.header('Authorization');
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).send('Access denied: Missing or invalid Authorization header');
  }
  const token = authHeader.replace('Bearer ', '');
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'secretkey');
    req.user = decoded;
    next();
  } catch (err) {
    res.status(401).send('Invalid token');
  }
};

// Routes
// Register User
app.post('/api/register', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).send('Email and password are required');
  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) return res.status(400).send('Email already exists');
    const hashedPassword = await bcrypt.hash(password, 12); // Increased salt rounds
    const user = new User({ email, password: hashedPassword });
    await user.save();
    res.status(201).send('User registered');
  } catch (err) {
    res.status(500).send('Server error');
  }
});

// Login User
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).send('Email and password are required');
  try {
    const user = await User.findOne({ email });
    if (!user || !await bcrypt.compare(password, user.password)) {
      return res.status(400).send('Invalid credentials');
    }
    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET || 'secretkey');
    res.send(token);
  } catch (err) {
    res.status(500).send('Server error');
  }
});

// Add Ingredient to Pantry
app.post('/api/pantry', authMiddleware, async (req, res) => {
  const { ingredient, quantity } = req.body;
  if (!ingredient || !quantity) return res.status(400).send('Ingredient and quantity are required');
  try {
    let pantry = await Pantry.findOne({ userId: req.user.userId });
    if (!pantry) {
      pantry = new Pantry({ userId: req.user.userId, ingredients: [] });
    }
    pantry.ingredients.push({ name: ingredient, quantity });
    await pantry.save();
    res.send('Ingredient added');
  } catch (err) {
    res.status(500).send('Server error');
  }
});

// Get Pantry
app.get('/api/pantry', authMiddleware, async (req, res) => {
  try {
    const pantry = await Pantry.findOne({ userId: req.user.userId });
    if (!pantry) return res.send('No ingredients found');
    const ingredientsList = pantry.ingredients.map(i => `${i.name}: ${i.quantity}`).join(', ');
    res.send(ingredientsList || 'No ingredients found');
  } catch (err) {
    res.status(500).send('Server error');
  }
});

// Get Recipe Suggestions
app.get('/api/recipes', authMiddleware, async (req, res) => {
  try {
    const pantry = await Pantry.findOne({ userId: req.user.userId });
    const pantryIngredients = pantry ? pantry.ingredients.map(i => i.name.toLowerCase()) : [];
    const recipes = await Recipe.find();
    const matchedRecipes = recipes.filter(recipe =>
      recipe.ingredients.every(ing => pantryIngredients.includes(ing.toLowerCase()))
    );
    const recipeList = matchedRecipes.map(r => r.name).join(', ');
    res.send(recipeList || 'No matching recipes found');
  } catch (err) {
    res.status(500).send('Server error');
  }
});

// Start Server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));

