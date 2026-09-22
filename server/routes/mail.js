import express from "express";
import { sendMail } from "../controllers/mail.js";
import { verifyToken } from "../middleware/verifyToken.js";

const router = express.Router();

router.post("/sendMail", verifyToken, sendMail);

export default router;
