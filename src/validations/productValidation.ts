import { body } from 'express-validator';

export const reviewValidation = [
  body('productId').isMongoId().withMessage('Invalid productId'),
  body('userId').isMongoId().withMessage('Invalid userId'),
  body('rating').isInt({ min: 1, max: 5 }).withMessage('Rating must be an integer between 1 and 5'),
  body('comment').trim().notEmpty().withMessage('Comment cannot be empty'),
];