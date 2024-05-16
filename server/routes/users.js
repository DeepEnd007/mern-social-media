import express from "express";
import {
  getUser,
  getUserFriends,
  addRemoveFriend,
} from "../controllers/users.js";
import { verifyToken } from "../middleware/auth.js";

const router = express.Router();

/*Read*/

router.get("/:id", verifyToken, getUser);
router.get("/:id/friend", verifyToken, getUserFriends);

/*UpDate*/
router.patch("/:id/:friendId", verifyToken, addRemoveFriend);

export default router;
