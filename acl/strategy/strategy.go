package strategy

type Strategy interface {
	Enforce() error
}
