// CWE-312: a password written to a Core Data object created with
// `NSEntityDescription.insertNewObject(forEntityName:into:)` whose class is not
// resolved as an `NSManagedObject` subclass (for example an Xcode-generated class).

protocol LegacyUser: AnyObject {
  var email: String { get set }
  var password: String { get set }
  var firstname: String { get set }
}

class LoginConfiguration {
  var password: String = ""
}

func registerUser(_ email: String, _ password: String, _ firstname: String, context: NSManagedObjectContext) -> LegacyUser {
  let user = NSEntityDescription.insertNewObject(forEntityName: "User", into: context) as! LegacyUser
  user.password = password // $ cleartextStorage
  // GOOD: not sensitive
  user.firstname = firstname
  return user
}

func configure(_ password: String) -> LoginConfiguration {
  // GOOD: not a Core Data object
  let config = LoginConfiguration()
  config.password = password
  return config
}
