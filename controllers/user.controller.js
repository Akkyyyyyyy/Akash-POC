
import { User } from '../models/user.model.js';

export const getAllUser = async (req, res) => {
    try {
        const users = await User.find();
        res.status(200).json(users);
    } catch (error) {
        res.status(500).json({ message: 'Failed to fetch users', error: error.message });
    }
};

export const register = async (req, res) => {
  try {
    const { username, email, phone, dob, gender, password } = req.body;
    if (!username || !email || !password || !phone || !dob || !gender) {
      return res.status(400).json({
        message: "Something is missing, please check!",
        success: false,
      });
    }
    const user = await User.findOne({ email });
    if (user) {
      return res.status(400).json({
        message: "Email Already Exist!",
        success: false,
      });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    await User.create({
      username,
      email,
      phone,
      dob,
      gender,
      password: hashedPassword,
    });
    return res.status(200).json({
      message: "Account Created!",
      success: true,
    });
  } catch (error) {
    console.log(error);
  }
};

export const login = async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(401).json({
        message: "Something is missing, please check!",
        success: false,
      });
    }

    let user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({
        message: "User doesn't exist!",
        success: false,
      });
    }
    const isPasswordMatch = await bcrypt.compare(password, user.password);
    if (!isPasswordMatch) {
      return res.status(401).json({
        message: "incorrect Password!",
        success: false
      });
    }

    const token = await jwt.sign({ userId: user._id }, process.env.SECRET_KEY, {
      expiresIn: "1d",
    });

    // const PopulatedPosts = await Promise.all(
    //   user.posts.map(async(postId)=>{
    //     const post = await Post.findById(postId);
    //     if(post.author.equals(user._id)){
    //       return post;
    //     }
    //     return null;
    //   })
    // )

    user = {
      _id: user._id,
      username: user.username,
      email: user.email,
      phone: user.phone,
      dob: user.dob,
      gender: user.gender
    };
    return res
      .cookie("token", token, {
        httpOnly: true,
        sameSite: "strict",
        maxAge: 1 * 24 * 60 * 60 * 1000,
      })
      .json({
        message: `Welcome Back ${user.username}`,
        success: true,
        user
      });
  } catch (error) {
    console.log(error);
  }
};

export const logout = async (_, res) => {
  try {
    return res.cookie("token", "", { maxAge: 0 }).json({
      message: 'Logged out Successfully.',
      success: true
    });
  } catch (error) {
    console.log(error);
  }
}