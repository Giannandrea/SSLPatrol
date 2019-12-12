class String
  def to_boolean
  	return false unless self
    self.downcase == 'true'
  end
end

class Integer
  def to_boolean
    to_s.to_boolean
  end
end