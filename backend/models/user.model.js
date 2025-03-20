const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
    username: { 
        type: String, 
        required: true, 
        unique: true, 
        trim: true, 
        minlength: 3, 
        maxlength: 50 
    },
    password: { 
        type: String, 
        required: true, 
        trim: true 
    },
    email: { 
        type: String, 
        required: true, 
        unique: true, 
        trim: true 
    },
    phone: { 
        type: String, 
        required: true, 
        trim: true 
    },
    role: { 
        type: String, 
        required: true, 
        trim: true 
    },
    courses: [{
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Course'
    }],
}, { timestamps: true });

module.exports = mongoose.model('User', userSchema);