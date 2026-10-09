const { Sequelize, DataTypes } = require('sequelize')
const vm = require('vm')

const sequelize = new Sequelize('sqlite::memory:')
const Profile = sequelize.define('Profile', { bio: DataTypes.STRING })

async function showBio (id, ctx) {
  const profile = await Profile.findOne({ where: { id } })
  vm.runInContext(profile.bio, ctx) // BAD
  const counted = await Profile.findAndCountAll()
  eval(counted.rows[0].bio) // BAD
  const created = Profile.build({ bio: '1 + 1' })
  eval(created.bio) // GOOD - not read from the database
}

module.exports = { showBio }
