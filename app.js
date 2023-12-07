const express = require("express")
const app = express()
const cors = require("cors")
const dotenv = require("dotenv")
const cookieParser = require("cookie-parser")

//Setting up config.env file variable
dotenv.config({ path: "./config/config.env" })

//Handle uncaught exceptions
process.on("uncaughtException", err => {
  console.log(`ERROR: ${err.stack}`)
  console.log("Shutting down due to uncaught exception")
  process.exit(1)
})

//Setting up database connection
const connection = require("./config/database")

//Setting up body parser
app.use(express.json())

//Setting up cookie parser
app.use(cookieParser())

//Setting up CORS
app.use(cors())

//Importing routes
const route = require("./route")

//Mounting routes
app.use("/", route)

//Handle unhandled routes
// app.all("*", (req, res, next) => {
//   res.status(404).json({
//     success: false,
//     message: "Page not found"
//   })
// })

const PORT = process.env.PORT
const server = app.listen(PORT, () => {
  console.log(`Server started on port ${PORT} in ${process.env.NODE_ENV} mode`)
})

//Handle unhandled promise rejections
process.on("unhandledRejection", err => {
  console.log(`ERROR: ${err.stack}`)
  console.log("Shutting down the server due to unhandled promise rejection")
  server.close(() => {
    process.exit(1)
  })
})

app.get("/", (req, res) => {
  res.json({ message: "Hello from server! " })
})
