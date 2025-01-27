package store

import (
	"context"
	"errors"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

type MongoOptions func(*Mongo)

func WithMongoURL(url string) MongoOptions {
	return func(m *Mongo) {
		m.url = url
	}
}

func WithDatabase(database string) MongoOptions {
	return func(m *Mongo) {
		m.database = database
	}
}

func WithCollection(collection string) MongoOptions {
	return func(m *Mongo) {
		m.collection = collection
	}
}

func WithTTL(ttl time.Duration) MongoOptions {
	return func(m *Mongo) {
		m.ttl = ttl
	}
}

type model struct {
	ID         string    `bson:"id"`
	Data       []byte    `bson:"metadata"`
	Expiration time.Time `bson:"expiry"`
	CreatedAt  time.Time `bson:"created_at"`
}

type Mongo struct {
	url        string
	ttl        time.Duration
	database   string
	collection string
	client     *mongo.Collection
}

// Del implements store.Store.
func (m *Mongo) Del(ctx context.Context, key string) error {
	filter := bson.D{{Key: "id", Value: key}}
	result, err := m.client.DeleteOne(ctx, filter)
	if err != err {
		return err
	}

	if result.DeletedCount < 1 {
		return errors.New("session: error deleting document, maybe it doesn't exist")
	}

	return nil
}

// Get implements store.Store.
func (m *Mongo) Get(ctx context.Context, key string) ([]byte, error) {
	res := model{}
	filter := bson.D{{Key: "id", Value: key}}
	result := m.client.FindOne(ctx, filter)

	if err := result.Decode(&res); err != nil {
		return nil, err
	}

	return res.Data, nil
}

// Set implements store.Store.
func (m *Mongo) Set(ctx context.Context, key string, value []byte, _ time.Duration) error {
	doc := model{
		ID:        key,
		Data:      value,
		CreatedAt: time.Now().UTC(),
	}
	result, err := m.client.InsertOne(ctx, doc)
	if err != nil {
		return err
	}

	if result.InsertedID == nil {
		return errors.New("session: can not validated if session was created")
	}

	return nil
}

func NewMongoDBStore(opts ...MongoOptions) (*Mongo, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()
	cfg := &Mongo{
		url:        "mongodb://localhost:27017",
		database:   "test-db",
		collection: "sessions",
	}
	for _, opt := range opts {
		opt(cfg)
	}

	client, err := mongo.Connect(options.Client().ApplyURI(cfg.url))
	if err != nil {
		return nil, err
	}

	err = client.Ping(ctx, nil)
	if err != nil {
		return nil, err
	}

	cfg.client = client.Database(cfg.database).Collection(cfg.collection)
	ttl := int32(cfg.ttl.Seconds())
	idx := []mongo.IndexModel{
		{
			Keys:    bson.D{{Key: "id", Value: 1}},
			Options: options.Index().SetUnique(true).SetExpireAfterSeconds(0),
		},
		{
			Keys:    bson.D{{Key: "created_at", Value: 1}},
			Options: options.Index().SetExpireAfterSeconds(ttl),
		},
	}

	_, err = cfg.client.Indexes().CreateMany(ctx, idx)
	if err != nil {
		return nil, err
	}

	return cfg, nil
}

var _ Store = (*Mongo)(nil)
