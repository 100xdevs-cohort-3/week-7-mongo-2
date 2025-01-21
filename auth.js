const jwt = require("jsonwebtoken");
const JWT_SECRET = "s3cret";

function auth(req, res, next) {
    const token = req.headers.authorization;

    try {
        const response = jwt.verify(token, JWT_SECRET);
        req.userId = response.userId;
        next();
    } catch (error) {
        res.status(403).json({
            message: "Incorrect creds"
        });
    }
}

module.exports = {
    auth,
    JWT_SECRET
}