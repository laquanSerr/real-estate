import User from '../models/user.model.js';
import bcrypt from 'bcrypt';
import { errorHandler } from '../utils/error.js';
import jwt from 'jsonwebtoken';


//export const signup = async (req, res, next) => {
  //const { username, email, password } =  req.body;
  //const newUser = new User({ username, email, password });
  //try {
    //await newUser.save();
    //res.status(201).json({ message: "User created successfully" });
  //} catch (error) {
    //next(error);
  //}
//};
export const signup = async (req, res, next) => {
  const { username, email, password } = req.body;

  try {
    const salt = bcrypt.genSaltSync(10);
    const hashedPassword = bcrypt.hashSync(password, salt);

    const newUser = new User({
      username,
      email,
      password: hashedPassword,
    });

    await newUser.save();

    // Return sanitized user (no password)
    const { password: _, ...userWithoutPassword } = newUser._doc;
    res.status(201).json({ user: userWithoutPassword });

  } catch (error) {
    next(error);
  }
};

export const signin = async (req, res, next) => {
  const { email, password } = req.body;

  try {
    const validUser = await User.findOne({ email });
    if (!validUser) return next(errorHandler(404, 'User not found'));

    const validPassword = bcrypt.compareSync(password, validUser.password);
    if (!validPassword) return next(errorHandler(401, 'Wrong credentials'));

    const token = jwt.sign(
      { id: validUser._id },
      process.env.JWT_SECRET,
      { expiresIn: '15m' }
    );

    const refreshToken = jwt.sign(
      { id: validUser._id },
      process.env.JWT_REFRESH_SECRET,
      { expiresIn: '7d' }
    );

    // Sanitize user before sending
    const { password: _, ...userWithoutPassword } = validUser._doc;

    res
      .cookie('access_token', token, {
        httpOnly: true,
        maxAge: 15 * 60 * 1000, // 15 minutes
        secure: process.env.NODE_ENV === 'production',
      })
      .cookie('refresh_token', refreshToken, {
        httpOnly: true,
        sameSite: 'Strict',
        maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
        secure: process.env.NODE_ENV === 'production',
      })
      .status(200)
      .json({ user: userWithoutPassword });
  } catch (error) {
    next(error);
  }
};
export const google = async (req, res, next) => {
  const { email, name, photo } = req.body;

  try {
    let user = await User.findOne({ email });

    if (!user) {
      const generatedPassword = Math.random().toString(36).slice(-8) + Math.random().toString(36).slice(-8);
      const hashedPassword = bcrypt.hashSync(generatedPassword, 10);

      user = new User({
        username: name.split(' ').join('').toLowerCase() + Math.floor(Math.random() * 1000),
        email,
        password: hashedPassword,
        avatar: photo,
        fromGoogle: true,
      });

      await user.save();
    }

    // Sanitize user object before sending
    const { password: _, ...userWithoutPassword } = user._doc;

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
      expiresIn: '15m',
    });

    res
      .cookie('access_token', token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        maxAge: 15 * 60 * 1000, // 15 minutes
      })
      .status(200)
      .json({ user: userWithoutPassword });
  } catch (error) {
    next(error);
  }
};