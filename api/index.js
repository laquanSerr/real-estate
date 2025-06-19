import express from 'express';
import mongoose from 'mongoose';
import dotenv from 'dotenv';
dotenv.config();

mongoose
  .connect(process.env.MONGO)
  .then(() => {
      console.log('Connected to MongoDB');
  })
  .catch((err) => {
    console.log(err);
  });

const app = express();

app.get('/', (req, res) => {
  res.send('<h1>Hello from Express</h1>');
});

app.listen(3000, () =>{
  console.log('Server listening on port 3000!');
});