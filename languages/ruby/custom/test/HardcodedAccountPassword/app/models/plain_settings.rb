# Not an ActiveRecord model.
class PlainSettings
  def self.create(**opts)
    opts
  end
end
