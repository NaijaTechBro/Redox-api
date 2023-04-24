const mongoose = require("mongoose")

const blogSchema = mongoose.Schema({
    title: {
        type: String,
        required: [true, "Please add your title"]
    },
    subtitle: {
        type: String
    },
    user: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "Subcriber"
    },
    image: {
        type: String,
    },
    body: {
        type: String,
        required: true
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
},
{
    timestamps: true,
});

module.exports = mongoose.model("Blog", blogSchema);