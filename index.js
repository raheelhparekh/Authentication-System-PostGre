import express from "express";
import dotenv from "dotenv";
import cors from "cors";
import cookieParser from "cookie-parser";

import userRoutes from "./routes/user.routes.js"

dotenv.config();
const app = express();
const port = process.env.PORT || 4000;
app.use(
  cors({
    origin: process.env.BASE_URL,
    methods: ["GET", "POST", "UPDATE", "DELETE"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);
app.use(express.json())
app.use(express.urlencoded({extended:true}))
app.use(cookieParser())

// custom routes
app.use("/api/v1/users", userRoutes)

app.get("/", (req, res) => {
  res.send("Hello raheel!");
});

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`);
});
