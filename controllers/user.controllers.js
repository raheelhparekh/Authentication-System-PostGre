import pkg from "@prisma/client";
const { PrismaClient } = pkg;
import bcrypt from "bcryptjs";
import crypto from "crypto";
import nodemailer from "nodemailer";
import jwt from "jsonwebtoken";

const prisma = new PrismaClient();

const registerUser = async (req, res) => {
  const { name, email, password, phone } = req.body;

  if (!name || !email || !password || !phone) {
    return res.status(400).json({
      message: "All fields are required",
      success: false,
    });
  }
  try {
    const existingUser = await prisma.user.findUnique({
      where: { email },
    });

    if (existingUser) {
      return res.status(400).json({
        message: "user already exists",
        success: false,
      });
    }

    // hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // generate a verification Token
    const verificationToken = crypto.randomBytes(32).toString("hex");

    const user = await prisma.user.create({
      data: {
        name,
        email,
        phone,
        password: hashedPassword,
        verificationToken,
      },
    });

    if (!user) {
      return res.status(400).json({
        message: "user not created succesfully",
        success: false,
      });
    }
    console.log("sending email ");

    try {
      // status token as email to user using nodemailer
      const transporter = nodemailer.createTransport({
        host: process.env.MAILTRAP_HOST,
        port: process.env.MAILTRAP_PORT,
        secure: false, // upgrade later with STARTTLS
        auth: {
          user: process.env.MAILTRAP_USERNAME,
          pass: process.env.MAILTRAP_PASSWORD,
        },
      });

      const info = transporter.sendMail({
        from: process.env.MAILTRAP_SENDEREMAIL, // statuser address
        to: user.email, // list of receivers
        subject: "Verify your Email", // Subject line
        text: `Please click on the following link ${process.env.BASE_URL}/api/v1/users/verify/${verificationToken}`,
        html: "<b>Hello world?</b>", // html body
      });

      console.log("Email sent:");
    } catch (error) {
      console.error("Error statusing email:", error);
      console.error(
        "Full error:",
        JSON.stringify(error, Object.getOwnPropertyNames(error))
      );
      return res.status(500).json({
        message: "Email not sent",
        success: false,
        error: error.message || error.toString(),
      });
    }

    return res.status(200).json({
      message: "user registered successfully",
      success: true,
    });
  } catch (error) {
    return res.status(500).json({
      message: "error occured while registering user",
      error,
      success: false,
    });
  }
};

const login = async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({
      message: "email and password is required",
      success: false,
    });
  }

  try {
    const findUser = await prisma.user.findUnique({
      where: { email },
    });
    if (!findUser) {
      return res.status(400).json({
        message: "user not found with this email",
        success: false,
      });
    }

    // verify password
    const isMatch = await bcrypt.compare(password, findUser.password);
    if (!isMatch) {
      return res.status(400).json({
        message: "password do not match",
        success: false,
      });
    }

    const token = jwt.sign({ id: findUser.id }, process.env.JWT_SECRET, {
      expiresIn: process.env.JWT_SECRET_EXPIRY,
    });

    const cookieOptions = {
      httpOnly: true,
      secure: true,
    };
    res.cookie("token", token, cookieOptions);

    return res.status(200).json({
      message: "User logged in",
      success: true,
      user: {
        id: findUser.id,
      },
    });
  } catch (error) {
    return res.status(400).json({
      message: "User not logged in",
      error,
      success: false,
    });
  }
};

const verifyUser = async (req, res) => {
  const { token } = req.params;

  if (!token) {
    return res.status(400).json({
      message: "no token found",
      success: false,
    });
  }

  try {
    const user = await prisma.user.findFirst({
      where: { verificationToken: token },
    });

    if (!user) {
      return res.status(400).json({
        message: "no user found with this token",
        success: false,
      });
    }

    await prisma.user.update({
      where: { id: user.id },
      data: {
        isVerified: true,
        verificationToken: undefined,
      },
    });

    return res.status(200).json({
      message: "user verified succesfully",
      success: true,
    });
  } catch (error) {
    return res.status(500).json({
      message: "error occured while verifiying user",
      error,
      success: false,
    });
  }
};

const getMe = async (req, res) => {
  try {
    const user = await prisma.user.findUnique({
      where: { id: req.user.id },
    });

    if (!user) {
      return res.status(400).json({
        message: "cannot find user",
        success: false,
      });
    }

    return res.status(200).json({
      user,
      message: "User found",
      success: true,
    });
  } catch (error) {
    return res.status(500).json({
      message: "error occured finding user",
      error,
      success: false,
    });
  }
};

const logout = async (req, res) => {
  try {
    res.cookie("token", "");

    res.status(200).json({
      message: "Logged out successfully",
      success: true,
    });
  } catch (error) {
    res.status(500).json({
      message: "error occurred while Logged out",
      error,
      success: false,
    });
  }
};

const forgotPassword = async (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({
      message: "email is required",
      success: false,
    });
  }

  try {
    const user = await prisma.user.findUnique({
      where: { email },
    });
    if (!user) {
      return res.status(400).json({
        message: "no user exists with this email",
        success: false,
      });
    }

    const token = crypto.randomBytes(32).toString("hex");

    await prisma.user.update({
      where: { id: user.id },
      data: {
        passwordResetToken: token,
        passwordResetExpiry: new Date(Date.now() + 10 * 60 * 1000).toISOString(),
      },
    });

    console.log("sending mail to user to reset password now");
    try {
      // status token as email to user using nodemailer
      const transporter = nodemailer.createTransport({
        host: process.env.MAILTRAP_HOST,
        port: process.env.MAILTRAP_PORT,
        secure: false, // upgrade later with STARTTLS
        auth: {
          user: process.env.MAILTRAP_USERNAME,
          pass: process.env.MAILTRAP_PASSWORD,
        },
      });

      const info = transporter.sendMail({
        from: process.env.MAILTRAP_SENDEREMAIL, // statuser address
        to: user.email, // list of receivers
        subject: "Reset your password", // Subject line
        text: `Please click on the following link to reset your password ${process.env.BASE_URL}/api/v1/users/reset-password/${token}`,
        html: "<b>Reset Password</b>", // html body
      });

      console.log("Email sent:", info.messageId);
    } catch (error) {
      console.error("Error sending email:", error);
      console.error(
        "Full error:",
        JSON.stringify(error, Object.getOwnPropertyNames(error))
      );
      return res.status(500).json({
        message: "Email not sent",
        success: false,
        error: error.message || error.toString(),
      });
    }

    return res.status(200).json({
      message: " Link has been sent to reset your password",
      success: true,
    });
  } catch (error) {
    return res.status(500).json({
      message: "error occured in forgot password",
      success: false,
    });
  }
};

const resetPassword = async (req, res) => {
  const { token } = req.params;
  const { password } = req.body;

  if (!token) {
    return res.status(400).json({
      message: "No token found",
      success: false,
    });
  }
  if (!password) {
    return res.status(400).json({
      message: "password cannot be empty",
      success: false,
    });
  }

  try {
    const user = await prisma.user.findFirst({
      where: {
        passwordResetToken: token,
        passwordResetExpiry: { gt: new Date().toISOString(), },
      },
    });

    if (!user) {
      return res.status(400).json({
        message: "no such user found in database",
        success: false,
      });
    }

    await prisma.user.update({
      where: { id: user.id },
      data: {
        password: await bcrypt.hash(password, 10),
        passwordResetToken: undefined,
        passwordResetExpiry: undefined,
      },
    });

    return res.status(200).json({
      message: "password reset done",
      success: true,
    });
  } catch (error) {
    return res.status(500).json({
      message: "some error occurred while resetting password",
      success: false,
      error,
    });
  }
};

export {
  registerUser,
  login,
  logout,
  forgotPassword,
  resetPassword,
  getMe,
  verifyUser,
};