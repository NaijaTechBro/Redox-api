const mongoose = require("mongoose")

const blogSchema = mongoose.Schema({
    title: {
        type: String,
        required: [true, "Please add your title"]
    },
    subtitle: {
        type: String
    },
    image: {
        type: String,
    },
    body: {
        type: String,
        required: true
    },
    quote: {
        type: String,
    },
    readingTime: {
        type: String,
    },
    createdAt: { 
        type: Date, 
        default: Date.now 
    },
    updatedAt: { 
        type: Date, 
        default: Date.now 
    },
})

module.exports = mongoose.model("Blog", blogSchema);