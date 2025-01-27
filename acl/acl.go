package acl

type Option func(*ACL)

type ACL struct {}

func New(opts ...Option)(*ACL, error){
    return &ACL{}, nil
}
