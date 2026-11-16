#import <Foundation/Foundation.h>
#import <CoreLocation/CoreLocation.h>

@interface CLSimulationManager : NSObject
- (void)clearSimulatedLocations;
- (void)appendSimulatedLocation:(CLLocation *)location;
- (void)flush;
- (void)startLocationSimulation;
- (void)stopLocationSimulation;
@end
