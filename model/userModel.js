const mongoose = require("mongoose")
const bcrypt = require("bcrypt")
const validator = require("validator")
const { ROLE_ADMIN, ROLE_USER } = require("../constants/index")

const userSchema = mongoose.Schema({
    user: {
        type: String,
        required: [false, "Please add a name"]
    },
    name: {
        type: String,
        required: [true, "Please add your name"]
    },
    email: {
        type: String,
        required: [true, "Please add your email"],
        unique: true,
        trim: true,
        minLength: 8,
        match: [
            /^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/,
            "Please enter a valid email"
        ]
    },
    password: {
        type: String,
        required: [true, "Please add a password"],
        minLength: [6, "Password must be up to 6 characters"]
    },
    passwordChangedAt: {
        type: Date,
    },
    pin: {
        type: Number,
        // required: [true, "Please create your 4 digit pin"],
        minLength: 4,
        maxLength: 4,
    },
    referralCode: { 
        type: String, unique: true 
    },
  referrer: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User' 
},
  referralCount: { 
    type: Number, 
    default: 0 
},
  referralBonus: { 
    type: Number, 
    default: 0 
},
    disabled: {
        type: String,
    },
    accountExpired: {
        type: Boolean,
    } ,
    accountLocked: {
        type: Boolean,
    },
    home_address: {
        type: String,
    },
    status: {
        type: String,
        default: 'Online',
    },
    city: {
        type: String,
    },
    state: {
        type: String,
    },
    postal_code: {
        type: String,
    },
    country: {
        type: String,
    },
    phone: {
        type: Number,
    },
    photo: {
        type: String,
        required: [true, "Please add an image"],
        default: "https://i.ibb.co/4pDNDk1/avatar.png"
    },
    vToken: {
        type: Object,
        default: {},
    },
    isVerified: {
        type: Boolean,
        default: false,
    },
    role: {
        type: String,
        require: true,
        default: "ROLE_USER",
        enum: [ROLE_ADMIN, ROLE_USER]
    },
    userAgent: {
        type: Array,
        required: true,
        default: [],
    },
}, {
    timestamps: true,
    minimize: false,
})

// Encrypt and hash password before save
userSchema.pre ("save", async function(next) {
    if(!this.isModified("password")) {
        return next()
    }

    // hash Password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(this.password, salt);
    this.password = hashedPassword;
    next();

})

module.exports = mongoose.model("User", userSchema);