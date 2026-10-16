// Package mongo is a minimal stub of go.mongodb.org/mongo-driver/mongo for testing.
package mongo

import "context"

type InsertOneResult struct{}

type InsertManyResult struct{}

type UpdateResult struct{}

type SingleResult struct{}

type Collection struct{}

func (coll *Collection) InsertOne(ctx context.Context, document interface{}) (*InsertOneResult, error) {
	return nil, nil
}

func (coll *Collection) InsertMany(ctx context.Context, documents []interface{}) (*InsertManyResult, error) {
	return nil, nil
}

func (coll *Collection) UpdateOne(ctx context.Context, filter interface{}, update interface{}) (*UpdateResult, error) {
	return nil, nil
}

func (coll *Collection) UpdateMany(ctx context.Context, filter interface{}, update interface{}) (*UpdateResult, error) {
	return nil, nil
}

func (coll *Collection) UpdateByID(ctx context.Context, id interface{}, update interface{}) (*UpdateResult, error) {
	return nil, nil
}

func (coll *Collection) ReplaceOne(ctx context.Context, filter interface{}, replacement interface{}) (*UpdateResult, error) {
	return nil, nil
}

func (coll *Collection) FindOne(ctx context.Context, filter interface{}) *SingleResult {
	return nil
}

func (coll *Collection) FindOneAndUpdate(ctx context.Context, filter interface{}, update interface{}) *SingleResult {
	return nil
}

func (coll *Collection) FindOneAndReplace(ctx context.Context, filter interface{}, replacement interface{}) *SingleResult {
	return nil
}
