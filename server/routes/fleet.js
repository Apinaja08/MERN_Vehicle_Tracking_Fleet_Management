import express from "express";
import { addFleet, deleteFleet, getAllFleets, getFleet, updateFleet, updateStatusFleet } from "../controllers/fleet.js";
import { verifyToken } from "../middleware/verifyToken.js";

const router = express.Router();

router.get("/getAllFleets", verifyToken, getAllFleets);
router.get("/getFleet/:id", verifyToken, getFleet);

router.put("/updateFleet/:id", verifyToken, updateFleet);
router.put("/updateStatusFleet", verifyToken, updateStatusFleet);

router.post("/addFleet", verifyToken, addFleet);

router.delete("/deleteFleet/:id", verifyToken, deleteFleet);

export default router;
