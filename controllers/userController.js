const connection = require("../config/database")
const catchAsyncErrors = require("../middleware/catchAsyncErrors")
const ErrorResponse = require("../utils/errorHandler")
const jwt = require("jsonwebtoken")

//View all users(Admin ONLY) => /api/v1/viewUsers
exports.viewUsers = catchAsyncErrors(async (req, res, next) => {
  const [rows, fields] = await connection.promise().execute("SELECT * FROM user")

  res.status(200).json({
    success: true,
    data: rows
  })
})

//View user profile => /api/v1/profile
exports.userProfile = catchAsyncErrors(async (req, res, next) => {
  const [row, fields] = await connection.promise().execute("SELECT * FROM user WHERE username = ?", [req.user.username])

  res.status(200).json({
    success: true,
    data: row
  })
})

//Update user profile => /api/v1/profile/update
exports.updateProfile = catchAsyncErrors(async (req, res, next) => {
  const [row, fields] = await connection.promise().execute("SELECT * FROM user WHERE username = ?", [req.user.username])
  //Not needed
  if (row.length === 0) {
    return next(new ErrorResponse("User not found", 404))
  }

  let update = ""
  if (req.body.email) {
    const updateEmail = await connection.promise().execute("UPDATE user SET email = ? WHERE username = ?", [req.body.email, req.user.username])
    update += "Email successfully updated!"
  }
  if (req.body.password) {
    const updatePassword = await connection.promise().execute("UPDATE user SET password = ? WHERE username = ?", [req.body.password, req.user.username])
    update += " Password successfully updated!"
  }
  const nullEmail = !req.body.email || req.body.email === ""
  const nullPass = !req.body.password || req.body.password === ""

  if (nullEmail && nullPass) {
    return next(new ErrorResponse("Update failed! Nothing was changed.", 500))
  }

  // if (nullEmail) {
  //   return next(new ErrorResponse("Update failed! Email not changed.", 500))
  // }

  // if (nullPass) {
  //   return next(new ErrorResponse("Update failed! Password not changed.", 500))
  // }

  // const result = await connection.promise().execute("UPDATE user SET email = ? WHERE username = ?", [req.body.email, req.params.username])
  // if (result[0].affectedRows === 0) {
  //   return next(new ErrorResponse("Failed to update user", 500))
  // }
  // update += "Email updated successfully!"

  // const result2 = await connection.promise().execute("UPDATE user SET email = ? WHERE username = ?", [req.body.email, req.params.username])
  // if (result2[0].affectedRows === 0) {
  //   return next(new ErrorResponse("Failed to update user", 500))
  // }
  // update += "Password update successfully!"

  // if(req.body.email ===  null || req.body.email === "") {

  //   const updated = await connection.promise().execute("UPDATE user SET email = ? WHERE username = ?", [req.body.email, req.params.username])
  //   update += "Email updated successfully!\n"
  // }

  // if(req.body.password != null && req.body.password != "") {
  //   const updated = await connection.promise().execute("UPDATE user SET password = ? WHERE username = ?",[req.body.password, req.params.username])
  //   update += "password updated successfully!"
  // }

  res.status(200).json({
    success: true,
    message: update
  })
})

//Create new UserGroup
exports.addGroup = catchAsyncErrors(async (req, res, next) => {
  // const newGroup = ""

  const validName = !req.body.group_name || req.body.group_name == ""
  if (validName) {
    return next(new ErrorResponse("Creation failed!"), 418)
  }
  console.log(req.body.group_name)
  const results = await connection.promise().execute("INSERT INTO usergroups VALUES (?)", [req.body.group_name])

  res.status(200).json({
    success: true,
    message: req.body.group_name + " successfully created!"
  })
})
