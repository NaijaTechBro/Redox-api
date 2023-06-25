const mongoose = require("mongoose")
const bcrypt = require("bcrypt")
const { ROLE_ADMIN, ROLE_BUSINESS, ROLE_CLIENT, ROLE_USER } = require("../constants/index")

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
    bank_name: {
        type: String,
        required: [false, "Please add a firstName"]
    },
    account_number: {
        type: String,
        required: [false, "Please add a firstName"]
    },
    account_name: {
        type: String,
        required: [false, "Please add a firstName"]
    },
    transfer_type: {
        type: String,
        required: [false, "Please add a firstName"]
    },
    transfer_recept_to_me: {
        type: String,
        required: [false, "Please add a firstName"]
    },
    transfer_recept_to_customer: {
        type: String,
        required: [false, "Please add a firstName"]
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
        enum: [ROLE_ADMIN, ROLE_USER, ROLE_CLIENT, ROLE_BUSINESS]
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