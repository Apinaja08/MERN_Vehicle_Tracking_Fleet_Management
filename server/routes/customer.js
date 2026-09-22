import express from "express";
import {
  login,
  addCustomer,
  getAllCustomers,
  getCustomer,
  updateCustomer,
  updateStatusCustomer,
  deleteCustomer,
} from "../controllers/customer.js";
import { verifyToken } from "../middleware/verifyToken.js";

const router = express.Router();

router.get("/getAllCustomers", verifyToken, getAllCustomers);
router.get("/getCustomer/:id", verifyToken, getCustomer);

router.put("/updateCustomer/:id", verifyToken, updateCustomer);
router.put("/updateStatusCustomer", verifyToken, updateStatusCustomer);

router.post("/addCustomer", verifyToken, addCustomer);
router.post("/login", login);

router.delete("/deleteCustomer/:id", verifyToken, deleteCustomer);

export default router;
