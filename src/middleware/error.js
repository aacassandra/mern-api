const errorHandler = (error, req, res, next) => {
    const { errorStatus, data, message } = error
    res.status(errorStatus).json({
        message,
        data
    })
}

module.exports = {
    errorHandler,
}