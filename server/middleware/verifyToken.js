import jwt from "jsonwebtoken";

export const verifyToken = (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json("You are not authenticated!");
  }

  const token = authHeader.split(" ")[1];

  jwt.verify(token, process.env.JWT, (err, payload) => {
    if (err) {
      return res.status(403).json("Token is not valid!");
    }
    req.userId = payload.user._id;
    next();
  });
};
