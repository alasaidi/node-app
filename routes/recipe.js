import express from 'express';
import verifyToken from '../middleware/verifyToken.js';
import recipeControllers from '../controllers/recipe.js';

const router = express.Router();
router.get('/', verifyToken, recipeControllers.getAllRecipes);
router.post('/', verifyToken, recipeControllers.postRecipe);
router.get('/:id', verifyToken, recipeControllers.getOneRecipe);
router.put('/:id', verifyToken, recipeControllers.updateRecipe);
router.delete('/:id', verifyToken, recipeControllers.deleteRecipe);

// routes

export default router;
