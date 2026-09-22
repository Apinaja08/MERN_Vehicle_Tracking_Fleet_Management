import express from "express";
import { addRoute, getAllRoutes, updateStatusRoute } from "../controllers/route.js";
import { verifyToken } from "../middleware/verifyToken.js";

const router = express.Router();

router.get("/getAllRoutes", verifyToken, getAllRoutes);

router.post("/addRoute", verifyToken, addRoute);

router.put("/updateStatusRoute/:id", verifyToken, updateStatusRoute);

export default router;
