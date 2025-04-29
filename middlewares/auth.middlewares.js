import jwt from "jsonwebtoken"

const isLoggedIn = async (req, res, next) => {
  try {
    const token = req.cookies?.token;

    if (!token) {
      return res.status(400).json({
        message: "did not find token in cookie",
        success: false,
      });
    }

    const decodedData = jwt.verify(token, process.env.JWT_SECRET);
    console.log(decodedData);
    req.user = decodedData;
  } catch (error) {
    return res.status(500).json({
      message: "auth middleware failure",
      error,
      success: false,
    });
  }

  next();
};

export default isLoggedIn