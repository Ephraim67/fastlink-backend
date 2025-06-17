const mongoose = require('mongoose');
const bcrypt = require ('bcrypt');

const userSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true,
        trim: true,
    },
    email: {
        type: String,
        required: true,
        unique: true,
        lowercase: true,
        trim: true,
    },
    password: {
        type: String,
        required: true,
    },

    isAdmin: {
        type: Boolean,
        default: false,
    },

    isVerified: {
        type: Boolean,
        default: false,
    },
    verificationToken: {
        type: String,
    },

    resetTokenExpiry: {
        type: Date,
    },

}, { timestamps: true });

// Pre-save hook to hash the password before saving
userSchema.pre('save', async function (next) {
    if (!this.isModified('password')) return next();

    try {
        const hash = await bcrypt.hash(this.password, 12);
        this.password = hash;
        
        next();
    } catch (error) {
        next(error);
    }
    
});

// Instance method to campare password
userSchema.methods.verifyPassword = async function (enteredPassword) {
    try {
        return await bcrypt.compare(enteredPassword, this.password);
    } catch (error) {
        throw new Error('Password verification failed');
    }
};

// User DTO (Data Transfer Object) to be used in responses
userSchema.methods.toDTO = function () {
    return {
        id: this._id,
        name: this.name,
        email: this.email,
        isAdmin: this.isAdmin,
        isVerified: this.isVerified,
    };
};

module.exports = mongoose.model('User', userSchema);