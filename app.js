const express = require('express');
const mongoose = require('mongoose');
const connectDB = require('./config/database')


require('dotenv').config();

const authRoutes = require('./routes/auth');

const app = express();

console.log('MONGO_URI in main app:', process.env.MONGO_URI ? 'EXISTS' : 'UNDEFINED');


connectDB();

app.use(express.json());

app.use('/api/v1/auth/', authRoutes);

mongoose.connection.once('open', async () => {
    console.log('MongoDB connected');
    // await defaultUser();
})

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is running on ${PORT}`)
});