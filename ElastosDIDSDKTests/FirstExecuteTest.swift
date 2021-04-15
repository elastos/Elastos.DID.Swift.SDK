//
//  FirstExecuteTest.swift
//  ElastosDIDSDKTests
//
//  Created by 李爱红 on 2021/4/12.
//  Copyright © 2021 elastos. All rights reserved.
//

import XCTest
@testable import ElastosDIDSDK
import Swifter

class FirstExecuteTest: XCTestCase {
    
    var simulatedIDChain: SimulatedIDChain = SimulatedIDChain()
    
    override func setUp() {
        super.setUp()
        self.simulatedIDChain.start()
    }
    
    override func tearDown() {
        super.tearDown()
        self.simulatedIDChain.httpServer.stop()
    }
    
    func test() {
        
    }
    
    func testShouldHandleTheRequestInDifferentTimeIntervals() {
        
        let path = "/a/:b/c"
        let queue = DispatchQueue(label: "com.swifter.threading")
        let hostURL: URL
        
        self.simulatedIDChain.httpServer.GET[path] = {
            print("You asked for " + $0.path)
            return .ok(.htmlBody("You asked for " + $0.path))
            
        }
        
        do {
            
//            #if os(Linux)
//            try server.start(9081)
//            hostURL = URL(string: "http://localhost:9081")!
//            #else
//            try self.simulatedIDChain.httpServer.start()
//            hostURL = URL(string: "http://localhost:9090")!
//            #endif
            hostURL = URL(string: "http://localhost:9090")!

            
            let requestExpectation = expectation(description: "Request should finish.")
            requestExpectation.expectedFulfillmentCount = 3
            
            (1...3).forEach { index in
                queue.asyncAfter(deadline: .now() + .seconds(index)) {
                    let task = URLSession.shared.executeAsyncTask(hostURL: hostURL, path: "resolve") { (_, response, _ ) in
                        requestExpectation.fulfill()
                        let statusCode = (response as? HTTPURLResponse)?.statusCode
                        print("statusCode = \(String(describing: statusCode))")
                    }
                    
                    task.resume()
                }
            }
            
        } catch let error {
            XCTFail("\(error)")
        }
        
        waitForExpectations(timeout: 10, handler: nil)
    }
    
//    func testShouldHandleTheSameRequestConcurrently() {
//
//        let path = "/a/:b/c"
//        self.simulatedIDChain.httpServer.GET[path] = { .ok(.htmlBody("You asked for " + $0.path)) }
//
//        var requestExpectation: XCTestExpectation? = expectation(description: "Should handle the request concurrently")
//
//        do {
//
//            try self.simulatedIDChain.httpServer.start()
//            let downloadGroup = DispatchGroup()
//
//            DispatchQueue.concurrentPerform(iterations: 3) { _ in
//                downloadGroup.enter()
//
//                let task = URLSession.shared.executeAsyncTask(path: path) { (_, response, _ ) in
//
//                    let statusCode = (response as? HTTPURLResponse)?.statusCode
//                    XCTAssertNotNil(statusCode)
//                    XCTAssertEqual(statusCode, 200)
//                    requestExpectation?.fulfill()
//                    requestExpectation = nil
//                    downloadGroup.leave()
//                }
//
//                task.resume()
//            }
//
//        } catch let error {
//            XCTFail("\(error)")
//        }
//
//        waitForExpectations(timeout: 15, handler: nil)
//    }
}

extension URLSession {
    
    func executeAsyncTask(
        hostURL: URL = URL(string: "http://localhost:8080")!,
        path: String,
        completionHandler handler: @escaping (Data?, URLResponse?, Error?) -> Void
    ) -> URLSessionDataTask {
        return self.dataTask(with: hostURL.appendingPathComponent(path), completionHandler: handler)
    }
}
