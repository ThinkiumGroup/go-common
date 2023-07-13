package abi

import (
	"errors"
	"fmt"
	"reflect"

	"github.com/ThinkiumGroup/go-common"
)

func (arguments Arguments) CopyEvent(v interface{}, values []interface{}) error {
	// make sure the passed value is arguments pointer
	if reflect.Ptr != reflect.ValueOf(v).Kind() {
		return fmt.Errorf("abi: event Unpack(non-pointer %T)", v)
	}
	if len(values) == 0 {
		if len(arguments.NonIndexed()) != 0 {
			return errors.New("abi: event attempting to copy no values while arguments are expected")
		}
		return nil // Nothing to copy, return
	}
	if arguments.isTuple() {
		return arguments.copyTupleEvent(v, values)
	}
	return arguments.copyAtomic(v, values[0])
}

// copyTuple copies a batch of values from marshalledValues to v.
func (arguments Arguments) copyTupleEvent(v interface{}, marshalledValues []interface{}) error {
	value := reflect.ValueOf(v).Elem()

	switch value.Kind() {
	case reflect.Struct:
		argNames := make([]string, len(arguments))
		for i, arg := range arguments {
			argNames[i] = arg.Name
		}
		var err error
		abi2struct, err := mapArgNamesToStructFields(argNames, value)
		if err != nil {
			return err
		}
		for i, arg := range arguments {
			field := value.FieldByName(abi2struct[arg.Name])
			if !field.IsValid() {
				return fmt.Errorf("abi: event field %s can't be found in the given value", arg.Name)
			}
			if err := set(field, reflect.ValueOf(marshalledValues[i])); err != nil {
				return err
			}
		}
	case reflect.Slice, reflect.Array:
		if value.Len() < len(marshalledValues) {
			return fmt.Errorf("abi: event insufficient number of arguments for unpack, want %d, got %d", len(arguments), value.Len())
		}
		for i := range arguments {
			if err := set(value.Index(i), reflect.ValueOf(marshalledValues[i])); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("abi:[2] cannot unmarshal tuple in to %v", value.Type())
	}
	return nil
}

func (abi ABI) UnpackEvent(v interface{}, topics []common.Hash, data []byte) error {
	if len(topics) == 0 {
		return errors.New("empty topics")
	}
	event, err := abi.EventByID(topics[0])
	if err != nil || event == nil {
		return fmt.Errorf("event is missing: %w", err)
	}
	args := event.Inputs
	dataArgs := args.NonIndexed()
	var values []interface{}
	if len(data) > 0 {
		values, err = dataArgs.Unpack(data)
		if err != nil {
			return err
		}
	}
	if len(dataArgs) != len(values) {
		return errors.New("values not match with data args")
	}

	var ret []interface{}
	indexes := 0
	for i, arg := range args {
		if arg.Indexed {
			indexes++
			j := 1 + i
			if j >= len(topics) {
				return fmt.Errorf("%d topic is missing", j)
			}
			value, err := toGoType(0, arg.Type, topics[j][:])
			if err != nil {
				return fmt.Errorf("%d topic unpack failed: %w", j, err)
			}
			ret = append(ret, value)
		} else {
			break
		}
	}
	ret = append(ret, values...)
	return args.CopyEvent(v, ret)
}
