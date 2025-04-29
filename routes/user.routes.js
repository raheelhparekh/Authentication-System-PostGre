import express from "express";
import { forgotPassword, getMe, login, logout, registerUser, resetPassword, verifyUser } from "../controllers/user.controllers.js";
import isLoggedIn from "../middlewares/auth.middlewares.js";

const router= express.Router()

router.post("/register", registerUser)
router.post("/login",login)
router.get("/me",isLoggedIn,getMe)
router.get("/verify/:token",verifyUser)
router.get("/logout",isLoggedIn,logout)
router.post("/forgot-password",forgotPassword)
router.post("/reset-password/:token",resetPassword)

export default router

