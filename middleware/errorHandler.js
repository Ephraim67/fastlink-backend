const errorHandler = (err, req, res, next) => {
  console.error(err.stack);
  
  // JWT errors
  if (err.name === 'UnauthorizedError') {
    return res.status(401).json({ message: 'Invalid token' });
  }
  
  // Mongoose validation error
  if (err.name === 'ValidationError') {
    return res.status(400).json({ message: err.message });
  }
  
  // Default to 500 server error
  res.status(500).json({ 
    message: process.env.NODE_ENV === 'production' 
      ? 'Something went wrong' 
      : err.message 
  });
};

module.exports = errorHandler;