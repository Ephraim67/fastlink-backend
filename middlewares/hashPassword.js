const bcrypt = require('bcrypt');

const hashedPasswordMiddleware = async (req, res, next) => {
    try {
        if (!req.body.password) {
            return res.status(400).json({ error: "Password is required"});
        }

        const salt = await bcrypt.genSalt(12);

        req.body.password = await bcrypt.hash(req.body.password, salt);

        next();
    } catch(error) {
        return res.status(500).json({ error: "Error hashing password" });
    }
};

module.exports = hashedPasswordMiddleware;