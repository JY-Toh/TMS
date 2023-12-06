// Check if the user is authenticated or not
const jwt = require("jsonwebtoken")
const connection = require("./config/database")
const ErrorHandler = require("./utils/errorHandler")

//Check if user account is valid
exports.isAuthenticatedUser = async (req, res, next) => {
  let token

  if (req.headers.authorization && req.headers.authorization.startsWith("Bearer")) {
    token = req.headers.authorization.split(" ")[1]
  }

  if (!token) {
    res.status(400).json({
      success: false,
      message: "Error: Login first to access the resource"
    })
  }

  let decoded
  try {
    decoded = jwt.verify(token, process.env.JWT_SECRET)
  } catch (e) {
    res.status(400).json({
      success: false,
      message: "Error: Token error"
    })
    return next(new ErrorHandler("Token error"))
  }
  connection.query("SELECT * FROM user WHERE username = ?", [decoded.username], async (error, result) => {
    req.user = result[0]

    if (req.user.is_disabled === 1) {
      res.status(400).json({
        success: false,
        message: "Error: User is disabled"
      })
    }

    next()
  })
}

// handling users roles
exports.authorizeRoles = (...roles) => {
  return (req, res, next) => {
    //User can have multiple groups delimited by ,{group},{group}. We need to split them into an array
    req.user.grouplist = req.user.grouplist.split(",")
    //if any of the user's groups is included in the roles array, then the user is authorized
    authorised = req.user.grouplist.some(r => roles.includes(r))
    if (!authorised) {
      res.status(400).json({
        success: false,
        message: "Error: Not allowed to access this resource"
      })
    }
    next()
  }
}

//Checking is a user account belongs to a specific group
exports.checkingGroup = async (req, res) => {
  const username = req.user.username
  const group = req.body.grouplist

  try {
    const result = await checkgroup(username, group)

    // Return successful check
    return res.status(200).json({
      result: result
    })
  } catch (e) {
    res.status(500).json({
      success: false,
      message: e
    })
    return
  }
}

async function checkgroup(userid, groupname) {
  const result = await connection.promise().query("SELECT * FROM user WHERE username = ? AND grouplist LIKE ?", [userid, `%,${groupname},%`])
  if (result[0][0]) {
    return true
  } else {
    return false
  }
}
