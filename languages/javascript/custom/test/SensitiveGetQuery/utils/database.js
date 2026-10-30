module.exports = {
    query: async function (sql, params) {
        return [[{ password_hash: '' }]];
    }
};
